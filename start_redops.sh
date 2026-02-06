#!/bin/bash

# Kill existing processes
echo "Cleaning up old processes..."
pkill -f "celery"
pkill -f "python3 app.py"

# Clean old data safely
echo "Cleaning old session data..."
rm -f data/redops3.db
rm -rf data/results/*
mkdir -p data/results
mkdir -p data/reports
mkdir -p data/wordlists

echo "Starting Redis..."
sudo /usr/bin/redis-server --daemonize yes

echo "Starting Celery Worker..."
export PYTHONPATH=$PYTHONPATH:.
# Using eventlet for better concurrency with SocketIO
celery -A core.tasks.celery worker --loglevel=info --detach -P eventlet

echo "Starting Redops Flask App..."
# Ensure dependencies are installed
pip install -r requirements.txt --quiet

python3 app.py
