from sqlmodel import SQLModel, create_engine, Session
from src.core.config import settings
import time
import logging
from sqlalchemy.exc import OperationalError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

engine = create_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,  
    pool_size=10,        
    max_overflow=20,
)


def init_db():
    max_retries = 30
    retry_wait = 2
    
    for attempt in range(max_retries):
        try:
            SQLModel.metadata.create_all(engine)
            logger.info("Database initialized successfully.")
            return
        except OperationalError as e:
            if attempt < max_retries - 1:
                logger.warning(f"Database connection failed (attempt {attempt + 1}/{max_retries}): {e}")
                logger.info(f"Retrying in {retry_wait} seconds...")
                time.sleep(retry_wait)
            else:
                logger.error("Could not connect to database after multiple retries.")
                raise e


def get_session():
    """FastAPI dependency for database sessions."""
    with Session(engine) as session:
        yield session
