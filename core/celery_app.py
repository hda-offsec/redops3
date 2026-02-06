from celery import Celery
import os
import sys

# Force redis import to check for conflicts
try:
    import redis
    if not hasattr(redis, 'Redis'):
        print(f"DEBUG: Conflict detected! redis module is {redis} from {getattr(redis, '__file__', 'unknown')}")
except ImportError:
    print("DEBUG: redis library not found")

def make_celery(app_name=__name__):
    # Use 127.0.0.1 instead of localhost for better compatibility
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
