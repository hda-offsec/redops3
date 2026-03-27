#!/bin/bash
set -e

# Function to kill offensive sub-processes (zombie scans)
clean_zombies() {
    echo "[*] Cleaning up offensive sub-processes..."
    OFFENSIVE_TOOLS=("nmap" "katana" "nuclei" "subfinder" "ffuf" "whatweb" "dnsrecon" "arjun" "sqlmap" "dirb" "subzy")
    for tool in "${OFFENSIVE_TOOLS[@]}"; do
        pkill -9 -f "$tool" || true
    done
    pkill -9 -f "chrome" || true
    
    # Nuclear cleanup for Celery & Python project processes
    echo "[*] Nuclear cleanup for project processes..."
    pkill -9 -f "celery -A core.tasks.celery" || true
    pkill -9 -f "python3 app.py" || true
    pkill -9 -f "tail -F data/celery.log" || true
}

# Function to kill processes on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down RedOps processes..."
    
    clean_zombies
    
    echo "Done. Bye!"
    exit
}

# Trap signals (Ctrl+C, termination)
trap cleanup SIGINT SIGTERM EXIT

# Kill existing processes at start
echo "Cleaning up old processes..."
clean_zombies
# Explicitly flush redis to avoid orphan tasks
redis-cli flushall &> /dev/null || true

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

# Optimized Playwright Check (Avoid re-downloading if already present)
PLAYWRIGHT_DIR="$HOME/.cache/ms-playwright"
if find "$PLAYWRIGHT_DIR" -maxdepth 2 -name "chromium-*" -type d 2>/dev/null | grep -q .; then
    # Already present, do nothing unless forced
    :
else
    echo "[!] Playwright browsers missing. This might take a few minutes..."
    mkdir -p .tmp
    TMPDIR=$PWD/.tmp ./venv/bin/python3 -m playwright install chromium
    rm -rf .tmp
fi

# Fast Dependency Check
echo "Verifying dependencies..."
if [ ! -f "data/.deps_installed" ] || [ "requirements.txt" -nt "data/.deps_installed" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt | grep -v "already satisfied" || true
    touch data/.deps_installed
else
    echo "[+] Dependencies up to date (cached)."
fi

# Pre-compile RedOps Python source code (catch syntax errors early)
echo "[*] Pre-compiling source files..."
./venv/bin/python3 -m compileall -q . -x "venv|tests|data|\.git" || echo "[!] Some compilation warnings occurred."


echo "[+] Starting Celery Worker (Pool: solo)..."
export PYTHONPATH=$PYTHONPATH:.
# Solo pool is the most stable on Python 3.13 / Kali
./venv/bin/celery -A core.tasks.celery worker --loglevel=info -P solo --logfile=data/celery.log &
CELERY_PID=$!

echo "[+] Starting Redops Flask App on http://0.0.0.0:5001"
# Force threading to avoid eventlet try-load
export ALLOW_UNSAFE_WERKZEUG=true
./venv/bin/python3 app.py || { echo "ERROR: Flask App failed to start!"; exit 1; }
