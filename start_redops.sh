#!/bin/bash
set -e

# Kill existing processes
echo "Cleaning up old processes..."
pkill -f "celery" || true
pkill -f "python3 app.py" || true

# Clean old data safely
echo "Cleaning old session data..."
# Keep DB if wanted? No, the user script removes it. 
# rm -f data/redops3.db

mkdir -p data/results
mkdir -p data/reports
mkdir -p data/wordlists

echo "Starting Redis..."
if ! command -v redis-server &> /dev/null; then
    echo "ERROR: redis-server not found. Please install redis."
    exit 1
fi
sudo redis-server --daemonize yes || echo "Redis might be already running..."

# Ensure we are in the right directory
cd "$(dirname "$0")"

# Install missing dependencies in the current environment
echo "Ensuring dependencies are installed..."
python3 -m pip install -r requirements.txt

echo "Starting Celery Worker..."
export PYTHONPATH=$PYTHONPATH:.
# Using threads pool instead of eventlet for Python 3.13 compatibility
celery -A core.tasks.celery worker --loglevel=info --detach -P threads

echo "Starting Redops Flask App..."
python3 app.py
