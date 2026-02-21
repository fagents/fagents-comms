#!/bin/bash
# Pull latest code and run tests.
# Usage: ./update.sh          — pull + test
#        ./update.sh restart  — pull + test + restart server

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "Pulling latest..."
git pull || { echo "ERROR: git pull failed"; exit 1; }

echo "Running tests..."
.venv/bin/python3 -m pytest test_server.py -q --tb=short || { echo "ERROR: tests failed"; exit 1; }

if [ "$1" = "restart" ]; then
    echo ""
    ./restart.sh
fi

echo ""
echo "Done."
