#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  MPF — Installation Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# --- Check prerequisites ---
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[!] $1 is not installed. Please install it first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓]${NC} $1 found"
}

echo -e "${YELLOW}[*] Checking prerequisites...${NC}"
check_cmd docker
check_cmd docker compose || check_cmd docker-compose
check_cmd python3
check_cmd node
check_cmd npm
echo ""

# --- Start infrastructure (Postgres + Redis) ---
echo -e "${YELLOW}[*] Starting PostgreSQL and Redis via Docker...${NC}"
docker compose up -d postgres redis
echo -e "${GREEN}[✓]${NC} Database and cache running"
echo ""

# --- Backend dependencies ---
echo -e "${YELLOW}[*] Setting up backend...${NC}"
cd backend

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[✓]${NC} Virtual environment created"
fi

source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}[✓]${NC} Python dependencies installed"

# Run database migrations
export MPF_DATABASE_URL="postgresql+psycopg://mpf:mpf@localhost:5432/mpf"
export MPF_REDIS_URL="redis://localhost:6379/0"
export MPF_STORAGE_ROOT="$(cd .. && pwd)/storage"

echo -e "${YELLOW}[*] Running database migrations...${NC}"
sleep 3  # wait for postgres to be ready
alembic upgrade head
echo -e "${GREEN}[✓]${NC} Database migrations applied"

deactivate
cd ..

# --- Frontend dependencies ---
echo -e "${YELLOW}[*] Setting up frontend...${NC}"
cd frontend
npm install
echo -e "${GREEN}[✓]${NC} Node dependencies installed"
cd ..

# --- Create storage directory ---
mkdir -p storage
echo -e "${GREEN}[✓]${NC} Storage directory ready"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}  Run ./start.sh to launch MPF${NC}"
echo -e "${GREEN}========================================${NC}"
