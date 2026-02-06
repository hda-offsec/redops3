#!/bin/bash

# Kill existing processes
pkill -f "celery"
pkill -f "python3 app.py"

echo "Starting Redis..."
sudo /usr/bin/redis-server --daemonize yes

echo "Starting Celery Worker..."
export PYTHONPATH=$PYTHONPATH:.
celery -A core.tasks.celery worker --loglevel=info --detach

echo "Starting Redops Flask App..."
python3 app.py
