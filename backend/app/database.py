import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# 1. Database Connection Configuration
# Uses DATABASE_URL from environment variables if set, otherwise defaults to SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

# 2. Create the SQLAlchemy Engine
# Note: connect_args={"check_same_thread": False} is required only for SQLite
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL)

# 3. Create SessionLocal class
# Each instance of SessionLocal will be a database session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# 4. Define Declarative Base Class
# Your models (e.g., Repository, Scan, Vulnerability) will inherit from this Base
class Base(DeclarativeBase):
    pass


# 5. Dependency for FastAPI Endpoints
# Yields a database session per request and ensures it closes afterwards
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()