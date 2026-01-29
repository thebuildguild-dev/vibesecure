from sqlmodel import SQLModel, create_engine, Session
from src.core.config import settings

engine = create_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,  
    pool_size=10,        
    max_overflow=20,
)


def init_db():
    """Create all tables on startup."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """FastAPI dependency for database sessions."""
    with Session(engine) as session:
        yield session
