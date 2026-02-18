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
redis-server --daemonize yes &> /dev/null || echo "Redis might be already running..."

# Ensure we are in the right directory early
cd "$(dirname "$0")"

# Uninstall fpdf ONLY if needed (checked by looking at venv)
if [ -d "venv/lib/python3.13/site-packages/fpdf" ] && [ ! -d "venv/lib/python3.13/site-packages/fpdf2" ]; then
    echo "Cleaning up PDF library conflicts (one-time fix)..."
    ./venv/bin/python3 -m pip uninstall -y fpdf pypdf &> /dev/null || true
fi

# Verifier Playwright (necessaire après emergency_cleanup.sh)
if [ ! -d "$HOME/.cache/ms-playwright" ]; then
    echo "[!] Playwright browsers missing. Installing Chromium..."
    mkdir -p .tmp
    TMPDIR=$PWD/.tmp ./venv/bin/python3 -m playwright install chromium
    rm -rf .tmp
fi

# Install missing dependencies
echo "Verifying dependencies..."
./venv/bin/python3 -m pip install -r requirements.txt | grep -v "already satisfied" || true

echo "[+] Starting Celery Worker (Pool: solo)..."
export PYTHONPATH=$PYTHONPATH:.
# Solo pool is the most stable on Python 3.13 / Kali
./venv/bin/celery -A core.tasks.celery worker --loglevel=info -P solo --logfile=data/celery.log &
CELERY_PID=$!

echo "[+] Starting Redops Flask App on http://0.0.0.0:5001"
# Force threading to avoid eventlet try-load
export ALLOW_UNSAFE_WERKZEUG=true
./venv/bin/python3 app.py || { echo "ERROR: Flask App failed to start!"; exit 1; }
