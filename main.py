from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, Query, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import select, update, delete, func, or_, desc
from datetime import timedelta
import secrets
from typing import Optional, List
import json

from database import engine, Base, SessionLocal, get_db
from models import User, WorkoutPlan, Exercise, UserRole
from schemas import (
    UserCreate, UserRead, Token, WorkoutPlanCreate, WorkoutPlanRead, WorkoutPlanUpdate,
    ExerciseCreate, ExerciseRead, ExerciseUpdate, StatsResponse, AdminUserUpdate,
    UserUpdate
)
from auth import get_password_hash, verify_password, create_access_token, verify_token

# ========== НАСТРОЙКА ПРИЛОЖЕНИЯ ==========
app = FastAPI(
    title="Fitness Tracker API",
    description="API для учета спортивных тренировок",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

sessions = {}
security = HTTPBearer()

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def get_current_user_session(request: Request) -> Optional[dict]:
    token = request.cookies.get("session_token")
    return sessions.get(token) if token else None

async def get_current_user_api(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = await verify_token(token)
    return payload

async def get_current_admin_api(current_user = Depends(get_current_user_api)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав"
        )
    return current_user

# ========== HTML РОУТЫ (ВЕБ-ИНТЕРФЕЙС) ==========
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user_session(request)
    
    # Получаем все публичные планы тренировок для отображения на главной
    result = db.execute(
        select(WorkoutPlan, User.username, User.full_name)
        .join(User, WorkoutPlan.owner_id == User.id)
        .where(WorkoutPlan.is_public == True)
        .order_by(desc(WorkoutPlan.created_at))
        .limit(12)  # Показываем до 12 планов на главной
    )
    
    public_plans_with_owners = result.all()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": current_user,
        "public_plans": public_plans_with_owners
    })

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[int] = None):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error
    })

@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).where(or_(User.email == username, User.username == username))
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(password, user.hashed_password):
        return RedirectResponse("/login?error=1", status_code=302)
    
    session_token = secrets.token_hex(32)
    sessions[session_token] = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value
    }
    
    access_token = create_access_token({
        "sub": user.username,
        "user_id": user.id,
        "role": user.role.value
    })
    
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(key="session_token", value=session_token, httponly=True)
    response.set_cookie(key="api_token", value=access_token)
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: Optional[int] = None):
    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": error
    })

@app.post("/register")
async def register(
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    full_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).where(or_(User.email == email, User.username == username))
    )
    if result.scalar_one_or_none():
        return RedirectResponse("/register?error=1", status_code=302)
    
    hashed = get_password_hash(password)
    new_user = User(
        email=email,
        username=username,
        hashed_password=hashed,
        full_name=full_name,
        role=UserRole.USER
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    session_token = secrets.token_hex(32)
    sessions[session_token] = {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role.value
    }
    
    access_token = create_access_token({
        "sub": new_user.username,
        "user_id": new_user.id,
        "role": new_user.role.value
    })
    
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(key="session_token", value=session_token, httponly=True)
    response.set_cookie(key="api_token", value=access_token)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user_session(request)
    if not current_user:
        return RedirectResponse("/login")
    
    # Получаем планы пользователя
    result = db.execute(
        select(WorkoutPlan)
        .where(WorkoutPlan.owner_id == current_user["id"])
        .order_by(desc(WorkoutPlan.created_at))
    )
    plans = result.scalars().all()
    
    api_token = request.cookies.get("api_token", "")
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "plans": plans,
        "token": api_token
    })

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user_session(request)
    if not current_user or current_user["role"] != "admin":
        return RedirectResponse("/")
    
    # Статистика для админа
    total_users = db.execute(select(func.count()).select_from(User)).scalar() or 0
    total_plans = db.execute(select(func.count()).select_from(WorkoutPlan)).scalar() or 0
    total_exercises = db.execute(select(func.count()).select_from(Exercise)).scalar() or 0
    
    api_token = request.cookies.get("api_token", "")
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "current_user": current_user,
        "stats": {
            "total_users": total_users,
            "total_plans": total_plans,
            "total_exercises": total_exercises
        },
        "token": api_token
    })

@app.get("/plan/{plan_id}", response_class=HTMLResponse)
async def plan_detail_page(
    plan_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = get_current_user_session(request)
    if not current_user:
        return RedirectResponse("/login")
    
    if current_user["role"] == "admin":
        result = db.execute(select(WorkoutPlan).where(WorkoutPlan.id == plan_id))
    else:
        result = db.execute(
            select(WorkoutPlan).where(
                WorkoutPlan.id == plan_id,
                WorkoutPlan.owner_id == current_user["id"]
            )
        )
    
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="План не найден")
    
    # Получаем упражнения плана
    result = db.execute(
        select(Exercise)
        .where(Exercise.workout_plan_id == plan_id)
        .order_by(Exercise.order)
    )
    exercises = result.scalars().all()
    
    api_token = request.cookies.get("api_token", "")
    
    return templates.TemplateResponse("plan_detail.html", {
        "request": request,
        "current_user": current_user,
        "plan": plan,
        "exercises": exercises,
        "token": api_token
    })

@app.get("/logout")
async def logout():
    response = RedirectResponse("/")
    response.delete_cookie("session_token")
    response.delete_cookie("api_token")
    return response

# ========== API РОУТЫ (CRUD ДЛЯ ПЛАНОВ ТРЕНИРОВОК) ==========
@app.post("/api/workout-plans/", response_model=WorkoutPlanRead)
async def create_workout_plan(
    plan_data: WorkoutPlanCreate,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    db_plan = WorkoutPlan(**plan_data.model_dump(), owner_id=current_user.user_id)
    db.add(db_plan)
    db.commit()
    db.refresh(db_plan)
    return db_plan

@app.get("/api/workout-plans/", response_model=List[WorkoutPlanRead])
async def get_workout_plans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan)
        .where(WorkoutPlan.owner_id == current_user.user_id)
        .offset(skip)
        .limit(limit)
        .order_by(desc(WorkoutPlan.created_at))
    )
    return result.scalars().all()

@app.get("/api/workout-plans/{plan_id}", response_model=WorkoutPlanRead)
async def get_workout_plan(
    plan_id: int,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan).where(
            WorkoutPlan.id == plan_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    plan = result.scalar_one_or_none()
    
    if not plan:
        raise HTTPException(status_code=404, detail="План тренировок не найден")
    return plan

@app.put("/api/workout-plans/{plan_id}", response_model=WorkoutPlanRead)
async def update_workout_plan(
    plan_id: int,
    plan_data: WorkoutPlanUpdate,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan).where(
            WorkoutPlan.id == plan_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    plan = result.scalar_one_or_none()
    
    if not plan:
        raise HTTPException(status_code=404, detail="План тренировок не найден")
    
    update_data = plan_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(plan, key, value)
    
    db.commit()
    db.refresh(plan)
    return plan

@app.delete("/api/workout-plans/{plan_id}")
async def delete_workout_plan(
    plan_id: int,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan).where(
            WorkoutPlan.id == plan_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    plan = result.scalar_one_or_none()
    
    if not plan:
        raise HTTPException(status_code=404, detail="План тренировок не найден")
    
    db.delete(plan)
    db.commit()
    return {"message": "План тренировок удален"}

# ========== API ДЛЯ УПРАЖНЕНИЙ ==========
@app.post("/api/exercises/", response_model=ExerciseRead)
async def create_exercise(
    exercise_data: ExerciseCreate,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan).where(
            WorkoutPlan.id == exercise_data.workout_plan_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="План тренировок не найден")
    
    db_exercise = Exercise(**exercise_data.model_dump())
    db.add(db_exercise)
    db.commit()
    db.refresh(db_exercise)
    return db_exercise

@app.get("/api/exercises/plan/{plan_id}", response_model=List[ExerciseRead])
async def get_exercises_by_plan(
    plan_id: int,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan).where(
            WorkoutPlan.id == plan_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="План тренировок не найден")
    
    result = db.execute(
        select(Exercise)
        .where(Exercise.workout_plan_id == plan_id)
        .order_by(Exercise.order)
    )
    return result.scalars().all()

@app.put("/api/exercises/{exercise_id}", response_model=ExerciseRead)
async def update_exercise(
    exercise_id: int,
    exercise_data: ExerciseUpdate,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(Exercise)
        .join(WorkoutPlan)
        .where(
            Exercise.id == exercise_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    exercise = result.scalar_one_or_none()
    
    if not exercise:
        raise HTTPException(status_code=404, detail="Упражнение не найдено")
    
    update_data = exercise_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(exercise, key, value)
    
    db.commit()
    db.refresh(exercise)
    return exercise

@app.delete("/api/exercises/{exercise_id}")
async def delete_exercise(
    exercise_id: int,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(Exercise)
        .join(WorkoutPlan)
        .where(
            Exercise.id == exercise_id,
            WorkoutPlan.owner_id == current_user.user_id
        )
    )
    exercise = result.scalar_one_or_none()
    
    if not exercise:
        raise HTTPException(status_code=404, detail="Упражнение не найдено")
    
    db.delete(exercise)
    db.commit()
    return {"message": "Упражнение удалено"}

# ========== СТАТИСТИКА ==========
@app.get("/api/stats", response_model=StatsResponse)
async def get_user_stats(
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(func.count()).select_from(WorkoutPlan)
        .where(WorkoutPlan.owner_id == current_user.user_id)
    )
    total_plans = result.scalar() or 0
    
    result = db.execute(
        select(func.count()).select_from(Exercise)
        .join(WorkoutPlan).where(WorkoutPlan.owner_id == current_user.user_id)
    )
    total_exercises = result.scalar() or 0
    
    result = db.execute(
        select(func.count()).select_from(WorkoutPlan)
        .where(
            WorkoutPlan.owner_id == current_user.user_id,
            WorkoutPlan.is_public == True
        )
    )
    public_plans = result.scalar() or 0
    
    return StatsResponse(
        total_plans=total_plans,
        total_exercises=total_exercises,
        public_plans=public_plans
    )

# ========== АДМИНИСТРАТИВНЫЕ API ==========
@app.get("/api/admin/users", response_model=List[UserRead])
async def admin_get_users(
    admin = Depends(get_current_admin_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).order_by(desc(User.created_at))
    )
    return result.scalars().all()

@app.get("/api/admin/stats")
async def admin_stats(
    admin = Depends(get_current_admin_api),
    db: Session = Depends(get_db)
):
    result = db.execute(select(func.count()).select_from(User))
    total_users = result.scalar() or 0
    
    result = db.execute(select(func.count()).select_from(WorkoutPlan))
    total_plans = result.scalar() or 0
    
    result = db.execute(select(func.count()).select_from(Exercise))
    total_exercises = result.scalar() or 0
    
    result = db.execute(
        select(User.role, func.count(User.id))
        .group_by(User.role)
    )
    roles_stats = {role.value: count for role, count in result.all()}
    
    return {
        "total_users": total_users,
        "total_workout_plans": total_plans,
        "total_exercises": total_exercises,
        "users_by_role": roles_stats
    }

@app.put("/api/admin/users/{user_id}/role")
async def admin_change_user_role(
    user_id: int,
    role_update: AdminUserUpdate,
    admin = Depends(get_current_admin_api),
    db: Session = Depends(get_db)
):
    if user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="Нельзя изменить свою роль")
    
    result = db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    if role_update.role:
        user.role = role_update.role
    
    db.commit()
    db.refresh(user)
    
    return {"message": f"Роль пользователя изменена на {user.role}"}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(
    user_id: int,
    admin = Depends(get_current_admin_api),
    db: Session = Depends(get_db)
):
    if user_id == admin.user_id:
        raise HTTPException(status_code=400, detail="Нельзя удалить себя")
    
    result = db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    db.delete(user)
    db.commit()
    
    return {"message": f"Пользователь {user.username} удален"}

@app.get("/api/admin/workout-plans", response_model=List[WorkoutPlanRead])
async def admin_get_all_plans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    admin = Depends(get_current_admin_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan)
        .offset(skip)
        .limit(limit)
        .order_by(desc(WorkoutPlan.created_at))
    )
    return result.scalars().all()

@app.delete("/api/admin/workout-plans/{plan_id}")
async def admin_delete_workout_plan(
    plan_id: int,
    admin = Depends(get_current_admin_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(WorkoutPlan).where(WorkoutPlan.id == plan_id)
    )
    plan = result.scalar_one_or_none()
    
    if not plan:
        raise HTTPException(status_code=404, detail="План тренировок не найден")
    
    db.delete(plan)
    db.commit()
    
    return {"message": f"План тренировок {plan_id} удален администратором"}

# ========== API ДЛЯ ПОЛЬЗОВАТЕЛЯ ==========
@app.get("/api/users/me", response_model=UserRead)
async def get_current_user_info(
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).where(User.id == current_user.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    return user

@app.put("/api/users/me", response_model=UserRead)
async def update_current_user(
    user_data: UserUpdate,
    current_user = Depends(get_current_user_api),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).where(User.id == current_user.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    update_data = user_data.model_dump(exclude_unset=True)
    
    if "email" in update_data and update_data["email"] != user.email:
        existing = db.execute(
            select(User).where(User.email == update_data["email"])
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=400, detail="Email уже используется")
    
    if "username" in update_data and update_data["username"] != user.username:
        existing = db.execute(
            select(User).where(User.username == update_data["username"])
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=400, detail="Имя пользователя уже используется")
    
    if "password" in update_data:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    
    for key, value in update_data.items():
        setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    return user

# ========== API АУТЕНТИФИКАЦИИ ==========
@app.post("/api/auth/register", response_model=UserRead)
async def api_register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).where(
            (User.email == user_data.email) | (User.username == user_data.username)
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email или имя пользователя уже существуют")
    
    hashed = get_password_hash(user_data.password)
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed,
        full_name=user_data.full_name,
        role=UserRole.USER
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=Token)
async def api_login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    result = db.execute(
        select(User).where(
            (User.email == username) | (User.username == username)
        )
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Неверные учетные данные")
    
    access_token = create_access_token({
        "sub": user.username,
        "user_id": user.id,
        "role": user.role.value
    })
    
    return {"access_token": access_token, "token_type": "bearer"}

# ========== ПУБЛИЧНЫЙ API ДЛЯ ГЛАВНОЙ СТРАНИЦЫ ==========
@app.get("/api/public/workout-plans", response_model=List[WorkoutPlanRead])
async def get_public_workout_plans(
    skip: int = Query(0, ge=0),
    limit: int = Query(12, ge=1, le=50),
    db: Session = Depends(get_db)
):
    """Получить список публичных планов тренировок (доступно без авторизации)"""
    result = db.execute(
        select(WorkoutPlan)
        .where(WorkoutPlan.is_public == True)
        .order_by(desc(WorkoutPlan.created_at))
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()

# ========== СИСТЕМНЫЕ РОУТЫ ==========
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    
    with SessionLocal() as session:
        result = session.execute(select(func.count()).select_from(User))
        count = result.scalar()
        
        if count == 0:
            admin = User(
                email="admin@example.com",
                username="admin",
                hashed_password=get_password_hash("admin123"),
                full_name="Администратор системы",
                role=UserRole.ADMIN
            )
            session.add(admin)
            session.commit()
            print("✅ Администратор по умолчанию создан")
            print("📧 Email: admin@example.com")
            print("🔑 Пароль: admin123")

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "fitness-tracker"}

@app.get("/api/docs-info")
async def docs_info():
    return {
        "swagger": "/api/docs",
        "redoc": "/api/redoc",
        "openapi": "/openapi.json"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)