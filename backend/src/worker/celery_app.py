import logging
from celery import Celery

try:
    from src.core.config import settings
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from src.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

REDIS_BROKER_URL = settings.redis_url
DATABASE_URL = settings.database_url
BACKEND_URL = settings.backend_url

logger.info(f"Celery broker: {REDIS_BROKER_URL}")

celery_app = Celery(
    "vibesecure_worker",
    broker=REDIS_BROKER_URL,
    backend=REDIS_BROKER_URL,
    include=["src.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.celery_task_time_limit,
    task_soft_time_limit=settings.celery_task_soft_time_limit,
    worker_prefetch_multiplier=settings.celery_worker_prefetch_multiplier,
    worker_concurrency=settings.celery_worker_concurrency,
    result_expires=settings.celery_result_expires,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)
