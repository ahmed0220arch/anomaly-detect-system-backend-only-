import os

import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from models import Base, UserDB

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://postgres:admin@localhost/pfe_project"
)
DEFAULT_ADMIN_EMAIL = "admin@neopolis.com"
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password must not be empty")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def seed_default_admin(db: Session) -> None:
    existing_admin = db.query(UserDB).filter(UserDB.email == DEFAULT_ADMIN_EMAIL).first()
    if existing_admin:
        print(f"[INIT] Admin user already exists: {DEFAULT_ADMIN_EMAIL}")
        return

    admin_user = UserDB(
        email=DEFAULT_ADMIN_EMAIL,
        hashed_password=hash_password(DEFAULT_ADMIN_PASSWORD),
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    print(f"[INIT] Default admin created: {DEFAULT_ADMIN_EMAIL}")


def main() -> None:
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        seed_default_admin(db)
    except Exception as exc:
        db.rollback()
        raise SystemExit(f"[CRITICAL] Failed to initialize admin user: {exc}") from exc
    finally:
        db.close()


if __name__ == "__main__":
    main()
