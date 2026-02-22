#!/bin/bash
# Restart the fagents-comms server
# Usage: ./restart.sh [PORT]

PORT="${1:-9753}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Stopping server on port $PORT..."
fuser -k $PORT/tcp 2>/dev/null && sleep 1
echo "Starting server..."
cd "$DIR" && nohup .venv/bin/python3 server.py --port $PORT </dev/null > server.log 2>&1 &
sleep 1
PID=$(fuser $PORT/tcp 2>/dev/null | awk '{print $1}')
if [ -n "$PID" ]; then
  echo "Server running (PID $PID) on port $PORT"
else
  echo "ERROR: Server failed to start. Check server.log"
  exit 1
fi
