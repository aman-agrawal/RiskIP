#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  IP Monitoring & Blocking System — Setup Script
# ═══════════════════════════════════════════════════════════════

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║    IP Monitoring & Blocking System — Setup              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Load NVM ───
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# ─── Backend Setup ───
echo -e "${YELLOW}[1/4] Installing backend dependencies...${NC}"
cd "$(dirname "$0")/backend"
pip3 install -r requirements.txt -q 2>/dev/null || pip install -r requirements.txt -q

# ─── Create data directory ───
echo -e "${YELLOW}[2/4] Creating data directory...${NC}"
mkdir -p data

# ─── Frontend Setup ───
echo -e "${YELLOW}[3/4] Installing frontend dependencies...${NC}"
cd ../frontend
npm install --silent 2>/dev/null

# ─── Done ───
echo -e "\n${GREEN}${BOLD}✓ Setup complete!${NC}\n"
echo -e "${CYAN}To start the application:${NC}"
echo -e ""
echo -e "  ${BOLD}Terminal 1 (Backend):${NC}"
echo -e "    cd backend"
echo -e "    python3 -m uvicorn main:app --reload --port 8000"
echo -e ""
echo -e "  ${BOLD}Terminal 2 (Frontend):${NC}"
echo -e "    cd frontend"
echo -e "    npm run dev"
echo -e ""
echo -e "  ${BOLD}Terminal 3 (Test Script):${NC}"
echo -e "    python3 test_script.py"
echo -e ""
echo -e "${CYAN}Login: ${BOLD}admin / admin123${NC}"
echo -e "${CYAN}Dashboard: ${BOLD}http://localhost:5173${NC}"
echo -e ""
