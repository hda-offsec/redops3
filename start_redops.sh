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

# Uninstall fpdf to avoid namespace conflict with fpdf2
echo "Cleaning up PDF library conflicts..."
python3 -m pip uninstall -y fpdf pypdf &> /dev/null || true

# Install missing dependencies
echo "Ensuring dependencies are installed..."
python3 -m pip install -r requirements.txt

echo "Starting Celery Worker (Pool: solo)..."
export PYTHONPATH=$PYTHONPATH:.
# Solo pool is the most stable on Python 3.13 / Kali
celery -A core.tasks.celery worker --loglevel=info --detach -P solo --logfile=data/celery.log

echo "Starting Redops Flask App..."
# Force threading to avoid eventlet try-load
python3 app.py
