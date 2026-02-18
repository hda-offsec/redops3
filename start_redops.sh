#!/bin/bash
set -e

# Function to kill processes on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down RedOps processes..."
    pkill -f "celery" || true
    pkill -f "python3 app.py" || true
    # Optionally stop redis if we started it as a daemon
    # sudo redis-cli shutdown || true
    echo "Done. Bye!"
    exit
}

# Trap signals (Ctrl+C, termination)
trap cleanup SIGINT SIGTERM EXIT

# Kill existing processes at start
echo "Cleaning up old processes..."
pkill -f "celery" || true
pkill -f "python3 app.py" || true

# Clean old data safely
mkdir -p data/results
mkdir -p data/reports
mkdir -p data/wordlists

echo "Starting Redis..."
if ! command -v redis-server &> /dev/null; then
    echo "ERROR: redis-server not found. Please install redis."
    exit 1
fi
sudo redis-server --daemonize yes &> /dev/null || echo "Redis might be already running..."

# Ensure we are in the right directory
cd "$(dirname "$0")"

# Uninstall fpdf to avoid namespace conflict with fpdf2
echo "Cleaning up PDF library conflicts..."
./venv/bin/python3 -m pip uninstall -y fpdf pypdf &> /dev/null || true

# Install missing dependencies
echo "Ensuring dependencies are installed..."
./venv/bin/python3 -m pip install -r requirements.txt
./venv/bin/python3 -m pip install --force-reinstall fpdf2 &> /dev/null

echo "🚀 Starting Celery Worker (Pool: solo)..."
export PYTHONPATH=$PYTHONPATH:.
# Solo pool is the most stable on Python 3.13 / Kali
# We run it in background but the trap will catch it
./venv/bin/celery -A core.tasks.celery worker --loglevel=info -P solo --logfile=data/celery.log &
CELERY_PID=$!

echo "🚀 Starting Redops Flask App..."
# Force threading to avoid eventlet try-load
export ALLOW_UNSAFE_WERKZEUG=true
./venv/bin/python3 app.py
