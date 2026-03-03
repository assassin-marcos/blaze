#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Blaze Installer — Linux / macOS / Unix
# ═══════════════════════════════════════════════════════════

set -e

BLUE='\033[94m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${BLUE}${BOLD}"
echo "    ██████╗ ██╗      █████╗ ███████╗███████╗"
echo "    ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝"
echo "    ██████╔╝██║     ███████║  ███╔╝ █████╗  "
echo "    ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝  "
echo "    ██████╔╝███████╗██║  ██║███████╗███████╗"
echo "    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝"
echo -e "${RESET}"
echo -e "    ${BOLD}Installer v2.0${RESET}\n"

# Check Python version
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
        major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null)
        minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ] 2>/dev/null; then
            PYTHON="$cmd"
            echo -e "  ${GREEN}✓${RESET} Python $ver found ($cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${RED}✗${RESET} Python 3.8+ required but not found."
    echo "    Install: https://www.python.org/downloads/"
    exit 1
fi

# Check pip
if ! "$PYTHON" -m pip --version &>/dev/null; then
    echo -e "  ${RED}✗${RESET} pip not found. Installing..."
    "$PYTHON" -m ensurepip --default-pip 2>/dev/null || {
        echo -e "  ${RED}✗${RESET} Failed to install pip. Please install manually."
        exit 1
    }
fi
echo -e "  ${GREEN}✓${RESET} pip available"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "  ${BOLD}Select installation method:${RESET}"
echo ""
echo "    1) pip install (recommended — installs 'blaze' command)"
echo "    2) Standalone binary (PyInstaller — single file, no deps)"
echo "    3) Development mode (editable pip install)"
echo ""
read -rp "  Choice [1]: " choice
choice="${choice:-1}"

case "$choice" in
    1)
        echo -e "\n  ${BLUE}Installing with pip...${RESET}"
        "$PYTHON" -m pip install "$SCRIPT_DIR" --quiet
        echo -e "  ${GREEN}✓${RESET} Installed! Run with: ${BOLD}blaze -u https://target.com${RESET}"
        ;;
    2)
        echo -e "\n  ${BLUE}Building standalone binary...${RESET}"
        "$PYTHON" -m pip install pyinstaller --quiet
        "$PYTHON" "$SCRIPT_DIR/build.py"
        ;;
    3)
        echo -e "\n  ${BLUE}Installing in development mode...${RESET}"
        "$PYTHON" -m pip install -e "$SCRIPT_DIR" --quiet
        echo -e "  ${GREEN}✓${RESET} Dev install complete! Run with: ${BOLD}blaze -u https://target.com${RESET}"
        ;;
    *)
        echo -e "  ${YELLOW}Invalid choice.${RESET}"
        exit 1
        ;;
esac

# Optional: install fast extras
echo ""
read -rp "  Install uvloop for faster I/O? (Linux/macOS only) [Y/n]: " uvloop_choice
uvloop_choice="${uvloop_choice:-Y}"
if [[ "$uvloop_choice" =~ ^[Yy] ]]; then
    "$PYTHON" -m pip install "blaze-scanner[fast]" --quiet 2>/dev/null || \
    "$PYTHON" -m pip install uvloop --quiet 2>/dev/null || true
    echo -e "  ${GREEN}✓${RESET} uvloop installed"
fi

echo ""
echo -e "  ${GREEN}${BOLD}Installation complete!${RESET}"
echo ""
echo -e "  Usage:"
echo -e "    ${BOLD}blaze -u https://target.com${RESET}              Smart scan"
echo -e "    ${BOLD}blaze -u https://target.com -r --depth 5${RESET} Recursive"
echo -e "    ${BOLD}blaze -u https://target.com -t 200${RESET}      200 threads"
echo -e "    ${BOLD}blaze --help${RESET}                             All options"
echo ""
