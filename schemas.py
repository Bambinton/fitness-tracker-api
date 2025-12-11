from pydantic import BaseModel, ConfigDict, Field, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum

# Enum для ролей пользователей
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

# --- User схемы ---
class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=100)

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserRead(UserBase):
    id: int
    role: UserRole
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# НОВАЯ: Схема для обновления пользователя
class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=100)
    password: Optional[str] = Field(None, min_length=6)

# --- WorkoutPlan схемы ---
class WorkoutPlanBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    difficulty: Optional[str] = Field(None, pattern="^(beginner|intermediate|advanced)$")
    duration_weeks: Optional[int] = Field(None, ge=1, le=52)
    is_public: bool = False

class WorkoutPlanCreate(WorkoutPlanBase):
    pass

class WorkoutPlanRead(WorkoutPlanBase):
    id: int
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)

# НОВАЯ: Схема для обновления плана тренировки
class WorkoutPlanUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    difficulty: Optional[str] = Field(None, pattern="^(beginner|intermediate|advanced)$")
    duration_weeks: Optional[int] = Field(None, ge=1, le=52)
    is_public: Optional[bool] = None

# --- Exercise схемы ---
class ExerciseBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    sets: Optional[int] = Field(None, ge=1, le=20)
    reps: Optional[str] = Field(None, max_length=50)
    rest_seconds: Optional[int] = Field(None, ge=0, le=600)
    order: Optional[int] = Field(None, ge=0)

class ExerciseCreate(ExerciseBase):
    workout_plan_id: int

class ExerciseRead(ExerciseBase):
    id: int
    workout_plan_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# НОВАЯ: Схема для обновления упражнения
class ExerciseUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    sets: Optional[int] = Field(None, ge=1, le=20)
    reps: Optional[str] = Field(None, max_length=50)
    rest_seconds: Optional[int] = Field(None, ge=0, le=600)
    order: Optional[int] = Field(None, ge=0)

# --- Token схемы ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    role: Optional[UserRole] = None

# --- Статистика ---
class StatsResponse(BaseModel):
    total_plans: int
    total_exercises: int
    public_plans: int

# --- Admin схемы ---
class AdminUserUpdate(BaseModel):
    role: Optional[UserRole] = None