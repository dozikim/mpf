#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  MPF — Starting Services${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Shutting down...${NC}"
    kill $BACKEND_PID $WORKER_PID $FRONTEND_PID 2>/dev/null
    echo -e "${GREEN}[✓]${NC} All services stopped"
    exit 0
}
trap cleanup SIGINT SIGTERM

# --- Ensure infrastructure is running ---
echo -e "${YELLOW}[*] Ensuring PostgreSQL and Redis are running...${NC}"
docker compose up -d postgres redis
echo -e "${GREEN}[✓]${NC} Infrastructure ready"
echo ""

# --- Environment variables ---
export MPF_DATABASE_URL="postgresql+psycopg://mpf:mpf@localhost:5432/mpf"
export MPF_REDIS_URL="redis://localhost:6379/0"
export MPF_STORAGE_ROOT="$(pwd)/storage"

# --- Start backend ---
echo -e "${YELLOW}[*] Starting backend (FastAPI on :8000)...${NC}"
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo -e "${GREEN}[✓]${NC} Backend started (PID: $BACKEND_PID)"

# --- Start Celery worker ---
echo -e "${YELLOW}[*] Starting Celery worker...${NC}"
celery -A app.workers.celery_app.celery worker --loglevel=info --concurrency=2 &
WORKER_PID=$!
echo -e "${GREEN}[✓]${NC} Worker started (PID: $WORKER_PID)"
deactivate
cd ..

# --- Start frontend ---
echo -e "${YELLOW}[*] Starting frontend (Vite on :5173)...${NC}"
cd frontend
npm run dev &
FRONTEND_PID=$!
echo -e "${GREEN}[✓]${NC} Frontend started (PID: $FRONTEND_PID)"
cd ..

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  MPF is running!${NC}"
echo -e "${GREEN}  Frontend:  http://localhost:5173${NC}"
echo -e "${GREEN}  Backend:   http://localhost:8000${NC}"
echo -e "${GREEN}  API Docs:  http://localhost:8000/docs${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}  Press Ctrl+C to stop all services${NC}"
echo ""

wait
