#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}==>${NC} ${GREEN}$1${NC}"
}

print_warn() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

# 1. INSTALL RUST (via rustup)
print_step "1/8: Checking/Installing Rust..."
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed."
fi

# 2. INSTALL CMAKE
print_step "2/8: Checking/Installing CMake..."
if ! command -v cmake &> /dev/null; then
    echo "CMake not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y cmake
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install cmake
        else
            print_warn "Homebrew not found. Please install CMake manually."
        fi
    else
        print_warn "Unsupported OS for automatic CMake installation. Please install CMake manually."
    fi
else
    echo "CMake is already installed."
fi

# 3. INSTALL PYTHON
print_step "3/8: Checking/Installing Python..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install python
        else
            print_warn "Homebrew not found. Please install Python manually."
        fi
    fi
else
    echo "Python3 is already installed."
fi

# 4. INSTALL WEBSITE REQUIREMENTS ( Frontend & Backend )
print_step "4/8: Checking/Installing Node.js & Website Dependencies..."
if ! command -v npm &> /dev/null; then
    echo "npm not found. Installing Node.js..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y nodejs npm
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install node
        else
            print_warn "Homebrew not found. Please install Node.js manually."
        fi
    fi
fi

if command -v npm &> /dev/null; then
    echo "Installing Backend dependencies..."
    (cd src/web/Backend && npm install)
    echo "Installing Frontend dependencies..."
    (cd src/web/Frontend && npm install)
else
    print_warn "npm is still not available. Skipping website dependencies."
fi

# 5. SETUP VIRTUAL ENVIRONMENT
print_step "5/8: Setting up Python Virtual Environment (.venv)..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi

# Activate venv
source .venv/bin/activate

# 6. INSTALL MATURIN
print_step "6/8: Installing Maturin..."
pip install --upgrade pip maturin

# 7. INSTALL REQUIREMENTS
print_step "7/8: Installing Python Requirements..."
pip install -r requirements.txt

# 8. BUILD NATIVE EXTENSION
print_step "8/8: Building Native Extension (tsarcore_native)..."
cd tsarcore_native
maturin develop --release --features parallel
cd ..
export PYTHONPATH="$PWD/src"

print_step "DONE!! Setup is complete."
echo ""
echo -e "${YELLOW}================================================================${NC}"
echo -e "${GREEN}Graffiti Protocol environment is ready!${NC}"
echo -e "To start running applications, benchmarks, or tests, please"
echo -e "activate the virtual environment first by running:"
echo -e ""
echo -e "    ${BLUE}source .venv/bin/activate${NC}"
echo -e ""
echo -e "${YELLOW}================================================================${NC}"
