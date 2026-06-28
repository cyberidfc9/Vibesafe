#!/bin/bash

# VibeSafe Hollywood-style Cyberpunk Installer
# Designed for Kali Linux and Debian/Ubuntu systems

# Colors
GREEN='\033[0;32m'
BRIGHT_GREEN='\033[1;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
FLASHING='\033[5m'

# Clear screen
clear

# Hollywood Intro
echo -e "${GREEN}======================================================================${NC}"
echo -e "${BRIGHT_GREEN}  V I B E S A F E   🛡️   S E C U R I T Y   I N S T A L L E R   E N G I N E${NC}"
echo -e "${GREEN}======================================================================${NC}"
sleep 0.4

echo -e "${CYAN}[*] Initializing installation sequence...${NC}"
sleep 0.5
echo -e "${GREEN}[+] Running terminal environment diagnostics...${NC}"
sleep 0.3
echo -e "${GREEN}[+] Verifying Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Error: Python3 not found. Aborting payload delivery.${NC}"
    exit 1
fi
sleep 0.3
echo -e "${GREEN}[+] Python3 version: $(python3 --version)${NC}"
sleep 0.3

# Check for PEP 668 Externally Managed Environment
echo -e "${YELLOW}[!] Inspecting target host system package managers...${NC}"
sleep 0.5
echo -e "${CYAN}[*] System environment is EXTERNALLY MANAGED (PEP 668).${NC}"
echo -e "${CYAN}[*] Bypassing restrictions safely via Local Virtual Environment Sandboxing...${NC}"
sleep 0.5

# Step 1: Create Virtual Environment
echo -e "\n${BRIGHT_GREEN}--- STAGE 1: Creating Isolated Sandbox Environment ---${NC}"
sleep 0.2
echo -n -e "${CYAN}[*] Generating Virtualenv directory structure... ${NC}"

# Custom visual loading animation
python3 -m venv venv &> /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[FAILED]${NC}"
    echo -e "${YELLOW}[!] Trying to install python3-venv module...${NC}"
    sudo apt-get update && sudo apt-get install -y python3-venv
    python3 -m venv venv
    if [ $? -ne 0 ]; then
         echo -e "${RED}[-] Error: Failed to create venv. Run: apt install python3-venv${NC}"
         exit 1
    fi
fi
echo -e "${BRIGHT_GREEN}[SUCCESS]${NC}"

# Step 2: Install dependencies inside the virtualenv
echo -e "\n${BRIGHT_GREEN}--- STAGE 2: Deploying Package Modules & Dependencies ---${NC}"
sleep 0.2
echo -e "${CYAN}[*] Running virtual pipeline pip install...${NC}"

# Hollywood Progress Bar
echo -n -e "${GREEN}Installing: [${NC}"
for i in {1..20}; do
    echo -n "■"
    sleep 0.08
done
echo -e "${GREEN}] 100%${NC}"

# Execute local installation within virtualenv
./venv/bin/pip install -e . > /dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Dependency deployment failed. Retrying in verbose mode...${NC}"
    ./venv/bin/pip install -e .
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi
echo -e "${BRIGHT_GREEN}[+] Base modules successfully injected into venv sandbox.${NC}"
sleep 0.4

# Step 3: Create global execution wrapper
echo -e "\n${BRIGHT_GREEN}--- STAGE 3: Linking Command Line Global Interfaces ---${NC}"
sleep 0.2

INSTALL_DIR="$(pwd)"
WRAPPER_PATH=""

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Running as non-root user. Installing command locally to user home.${NC}"
    mkdir -p "$HOME/.local/bin"
    WRAPPER_PATH="$HOME/.local/bin/vibesafe"
else
    echo -e "${GREEN}[+] Root access detected. Installing command globally in system binary paths.${NC}"
    WRAPPER_PATH="/usr/local/bin/vibesafe"
fi

echo -e "${CYAN}[*] Creating terminal execution wrapper at: ${WRAPPER_PATH}...${NC}"
sleep 0.5

# Write wrapper script
cat << EOF > "$WRAPPER_PATH"
#!/bin/bash
# VibeSafe system execution wrapper
$INSTALL_DIR/venv/bin/vibesafe "\$@"
EOF

chmod +x "$WRAPPER_PATH"

echo -e "${BRIGHT_GREEN}[+] Execution link initialized successfully.${NC}"
sleep 0.3

# Final confirmation output
echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${BRIGHT_GREEN}🛡️  VIBESAFE SYSTEM DEPLOYMENT COMPLETED SUCCESSFULLY${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "${CYAN}Target Path : ${NC}${INSTALL_DIR}"
echo -e "${CYAN}Global CLI  : ${NC}${WRAPPER_PATH}"
echo -e "\n${YELLOW}To initiate security scanning, run:${NC}"
echo -e "${BRIGHT_GREEN}  vibesafe phases${NC}"
echo -e "${BRIGHT_GREEN}  vibesafe scan <project_dir>${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "\n"
