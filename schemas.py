import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    is_active: bool


class LogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    level: str
    type: str
    message: str
    timestamp: datetime.datetime
    cpu_percent: float | None = None
    ram_percent: float | None = None
    project_id: int | None = None


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1)
    description: str | None = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    is_active: bool
    api_key: str
    created_at: datetime.datetime
