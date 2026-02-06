import os
try:
    import redis
except ImportError:
    raise ImportError("The 'redis' library is required for Celery but not found. Please run: pip install redis")
from celery import Celery

def make_celery(app_name=__name__):
    # Use 127.0.0.1 for local redis
    redis_url = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
    celery = Celery(
        app_name,
        broker=redis_url,
        backend=redis_url
    )
    
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=3600,
        broker_connection_retry_on_startup=True
    )
    
    return celery

celery = make_celery('redops_tasks')
