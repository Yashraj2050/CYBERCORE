#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🛡️  Starting CYBERCORE..."

# 1. Backend setup & run
echo "⚡ Starting Backend API on http://localhost:8000..."
cd "$ROOT_DIR/backend"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
fi
if [ ! -f ".env" ]; then
    cp .env.example .env
fi
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# 2. Frontend setup & run
echo "⚡ Starting Frontend on http://localhost:3000..."
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    npm install
fi
npm run dev &
FRONTEND_PID=$!

cleanup() {
    echo ""
    echo "Shutting down CYBERCORE..."
    kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    exit 0
}

trap cleanup INT TERM

echo ""
echo "✅ CYBERCORE is running!"
echo "   • Frontend:     http://localhost:3000"
echo "   • Backend API:  http://localhost:8000"
echo "   • API Docs:     http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services."

wait

