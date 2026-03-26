import csv
import io
import os
import secrets
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session
import datetime
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from auth import create_access_token, get_current_user, verify_password
from models import Base, LogDB, ProjectDB, UserDB
from schemas import LogResponse, ProjectCreate, ProjectResponse

# ---------------------------------------------------------
# 1. CONFIGURATION (The Connection String)
# ---------------------------------------------------------
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:admin@localhost/pfe_project")

# Create the connection engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Create the tables in the database
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------
# 3. DATA SHAPES (Pydantic)
# These check that the data sent to us is correct
# ---------------------------------------------------------
class LogCreate(BaseModel):
    level: str
    message: str
    project_id: int | None = None
    cpu_percent: float | None = None
    ram_percent: float | None = None

# Model for logs arriving from the external monitoring agent.
# timestamp is kept as a raw string so the agent controls the format.
class LogIncoming(BaseModel):
    timestamp: str   # e.g. "2026-03-05 14:22:01"
    level: str       # e.g. "INFO", "ERROR", "CRITICAL"
    message: str     # e.g. "FATAL: Database connection lost"
    cpu_percent: float | None = None
    ram_percent: float | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class LoginResponse(BaseModel):
    id: int
    email: EmailStr
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def infer_log_type(message: str) -> str:
    text = (message or "").lower()

    if any(token in text for token in ["database", "sql", "postgres", "mysql", "connection failed"]):
        return "Database"
    if any(token in text for token in ["login", "auth", "credential", "token", "negotiate", "password"]):
        return "Authentication"
    if any(token in text for token in ["network", "smtp", "socket", "dns", "endpoint", "ip "]):
        return "Network"
    if any(token in text for token in ["security", "privilege", "audit", "nt authority", "s-1-5-"]):
        return "Security"
    if any(token in text for token in ["service", "system", "svchost", "lsass", "logonui", "eventid"]):
        return "System"
    return "Other"

# ---------------------------------------------------------
# 4. THE SERVER (FastAPI)
# ---------------------------------------------------------


def ingest_rate_key(request: Request) -> str:
    # Prefer API key scoping for limiter; fallback to source IP.
    return request.headers.get("X-API-Key") or get_remote_address(request)


limiter = Limiter(key_func=ingest_rate_key)


app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Helper to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# POST: Create a new Log (The Agent will use this!)
@app.post("/logs/")
def create_log(log: LogCreate, db: Session = Depends(get_db)):
    # Create the new log object
    new_log = LogDB(
        level=log.level,
        message=log.message,
        project_id=log.project_id,
        cpu_percent=log.cpu_percent,
        ram_percent=log.ram_percent,
    )
    # Add it to the database
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    return new_log

# GET: Read all Logs (The Frontend will use this!)
@app.get("/logs/")
def read_logs(db: Session = Depends(get_db)):
    return db.query(LogDB).all()


@app.get("/api/logs", response_model=list[LogResponse])
def list_logs(
    level: str | None = Query(default=None),
    search: str | None = Query(default=None),
    log_date: str | None = Query(default=None, alias="date"),
    log_type: str | None = Query(default=None, alias="type"),
    project_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(get_current_user),
):
    query = db.query(LogDB)

    if level:
        query = query.filter(LogDB.level == level)

    if search:
        query = query.filter(LogDB.message.ilike(f"%{search}%"))

    if log_date:
        try:
            parsed_date = datetime.date.fromisoformat(log_date)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid date format. Use YYYY-MM-DD.") from exc

        query = query.filter(func.date(LogDB.timestamp) == parsed_date)

    if project_id is not None:
        query = query.filter(LogDB.project_id == project_id)

    rows = (
        query.with_entities(
            LogDB.id,
            LogDB.level,
            LogDB.message,
            LogDB.timestamp,
            LogDB.cpu_percent,
            LogDB.ram_percent,
            LogDB.project_id,
        )
        .order_by(LogDB.timestamp.desc(), LogDB.id.desc())
        .all()
    )

    responses: list[LogResponse] = []
    for log_id, log_level, log_message, log_timestamp, log_cpu, log_ram, log_project_id in rows:
        inferred_type = infer_log_type(str(log_message))
        if log_type and inferred_type.lower() != log_type.lower():
            continue

        responses.append(
            LogResponse(
                id=int(log_id),
                level=str(log_level),
                type=inferred_type,
                message=str(log_message),
                timestamp=log_timestamp,
                cpu_percent=float(log_cpu) if log_cpu is not None else None,
                ram_percent=float(log_ram) if log_ram is not None else None,
                project_id=int(log_project_id) if log_project_id is not None else None,
            )
        )

    return responses


@app.get("/api/logs/export")
def export_logs_csv(
    level: str | None = Query(default=None),
    search: str | None = Query(default=None),
    log_date: str | None = Query(default=None, alias="date"),
    log_type: str | None = Query(default=None, alias="type"),
    project_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(get_current_user),
):
    """Export the currently filtered logs as a downloadable CSV file."""
    query = db.query(LogDB)

    if level:
        query = query.filter(LogDB.level == level)
    if search:
        query = query.filter(LogDB.message.ilike(f"%{search}%"))
    if log_date:
        try:
            parsed_date = datetime.date.fromisoformat(log_date)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid date format. Use YYYY-MM-DD.") from exc
        query = query.filter(func.date(LogDB.timestamp) == parsed_date)
    if project_id is not None:
        query = query.filter(LogDB.project_id == project_id)

    rows = (
        query.with_entities(
            LogDB.id, LogDB.level, LogDB.message, LogDB.timestamp,
            LogDB.cpu_percent, LogDB.ram_percent, LogDB.project_id,
        )
        .order_by(LogDB.timestamp.desc(), LogDB.id.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Level", "Type", "Message", "Timestamp", "CPU %", "RAM %", "Project ID"])
    for log_id, log_level, log_message, log_timestamp, log_cpu, log_ram, log_pid in rows:
        inferred = infer_log_type(str(log_message))
        if log_type and inferred.lower() != log_type.lower():
            continue
        writer.writerow([log_id, log_level, inferred, log_message, log_timestamp, log_cpu, log_ram, log_pid])

    output.seek(0)
    filename = f"logs_export_{datetime.date.today()}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/projects", response_model=list[ProjectResponse])
def get_projects(db: Session = Depends(get_db)):
    return db.query(ProjectDB).all()


@app.post("/api/projects", response_model=ProjectResponse)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    api_key = secrets.token_urlsafe(32)

    new_project = ProjectDB(
        name=payload.name,
        description=payload.description,
        api_key=api_key,
    )

    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    return new_project


@app.post("/api/projects/{project_id}/revoke-key", response_model=ProjectResponse)
def revoke_project(
    project_id: int,
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(get_current_user),
):
    project = db.query(ProjectDB).filter(ProjectDB.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project.is_active = False
    db.commit()
    db.refresh(project)

    return project


@app.post("/api/projects/{project_id}/unrevoke-key", response_model=ProjectResponse)
def unrevoke_project(
    project_id: int,
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(get_current_user),
):
    project = db.query(ProjectDB).filter(ProjectDB.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project.is_active = True
    db.commit()
    db.refresh(project)

    return project


@app.post("/api/projects/{project_id}/rotate-key", response_model=ProjectResponse)
def rotate_project_key(
    project_id: int,
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(get_current_user),
):
    project = db.query(ProjectDB).filter(ProjectDB.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project.api_key = secrets.token_urlsafe(32)
    db.commit()
    db.refresh(project)

    return project


@app.post("/api/login", response_model=TokenResponse)
@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user_row = (
        db.query(UserDB.id, UserDB.email, UserDB.hashed_password, UserDB.is_active)
        .filter(UserDB.email == payload.email)
        .first()
    )
    if user_row is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id, user_email, hashed_password, is_active = user_row

    if not bool(is_active):
        raise HTTPException(status_code=403, detail="User account is inactive")

    if not verify_password(payload.password, str(hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    access_token = create_access_token(
        {
            "sub": str(user_email),
            "user_id": int(user_id),
        }
    )
    return TokenResponse(access_token=access_token)


# ---------------------------------------------------------
# SECURED INGEST ENDPOINT
# Route : POST /api/logs/ingest
# Auth  : X-API-Key header must equal the hardcoded secret
# Usage : Called by the external monitoring / simulator agent
# ---------------------------------------------------------

def verify_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> int:
    """
    Dependency that extracts the X-API-Key header and validates it.
    Returns the project ID that owns this key.
    Raises HTTP 401 immediately if the key is wrong or missing.
    """
    project_row = (
        db.query(ProjectDB.id, ProjectDB.is_active)
        .filter(ProjectDB.api_key == x_api_key)
        .first()
    )
    if project_row is None:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing X-API-Key header.",
        )

    project_id, is_active = project_row
    if not bool(is_active):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: project API key is revoked.",
        )

    return int(project_id)


@app.post("/api/logs/ingest", status_code=200)
@limiter.limit("100/minute")
def ingest_log(
    request: Request,
    log: LogIncoming | list[LogIncoming],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    project_id: int = Depends(verify_api_key),   # 401 if key is wrong
):
    """
    Receive one log object or a batch array from the external agent and persist it.

    - Validates the X-API-Key header via the `verify_api_key` dependency.
    - Parses the incoming timestamp string into a Python datetime object.
    - Inserts a new row into the `logs` table using the existing LogDB model.
    """
    incoming_logs = log if isinstance(log, list) else [log]

    new_entries: list[LogDB] = []
    for item in incoming_logs:
        # Parse the agent timestamp. Fall back to current UTC on format mismatch.
        try:
            parsed_ts = datetime.datetime.strptime(item.timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            parsed_ts = datetime.datetime.now(datetime.timezone.utc)

        new_entries.append(
            LogDB(
                level=item.level,
                message=item.message,
                timestamp=parsed_ts,
                project_id=project_id,
                cpu_percent=item.cpu_percent,
                ram_percent=item.ram_percent,
            )
        )

    db.add_all(new_entries)
    db.commit()

    # --- ML Anomaly Detection Hook (Simulation) ---
    project_name = db.query(ProjectDB.name).filter(ProjectDB.id == project_id).scalar() or "Unknown Project"
    from notifications import send_critical_alert_email
    import random

    for entry in new_entries:
        # Simulate ML anomaly detection. Triggers if "critical" or "fatal" is in log.
        is_anomaly = "fatal" in entry.message.lower() or "critical" in entry.level.lower()
        
        # If you want to force it to randomly trigger for testing, uncomment below:
        # is_anomaly = is_anomaly or random.random() < 0.05
        
        if is_anomaly:
            log_details = f"Level: {entry.level}\nTimestamp: {entry.timestamp}\nMessage: {entry.message}\nCPU: {entry.cpu_percent}%\nRAM: {entry.ram_percent}%"
            # Background tasks don't block the API response time!
            background_tasks.add_task(send_critical_alert_email, project_name, log_details)

    return {
        "status": "success",
        "count": len(new_entries),
        "ids": [entry.id for entry in new_entries],
    }
