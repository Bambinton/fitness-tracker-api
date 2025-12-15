from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# URL базы данных - SQLite файл
SQLALCHEMY_DATABASE_URL = "sqlite:///./fitness.db"

# Создаем движок БД
# check_same_thread=False - РАЗРЕШАЕТ работу из разных потоков
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}  # ВАЖНО для SQLite на Render
)

# Создаем фабрику сессий
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Базовый класс для моделей
Base = declarative_base()

# Функция для получения сессии БД
def get_db():
    """
    Возвращает сессию базы данных.
    Используется в FastAPI как зависимость.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()