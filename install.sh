#!/bin/bash
# ============================================================================
# Blaze Installer v2.3 — Unified Cross-Platform (Linux / macOS / Windows)
# Supports: native Linux, macOS, Git Bash, MSYS2, MinGW, WSL
# ============================================================================

set -e

# ---------------------------------------------------------------------------
# Color support — degrade gracefully on Windows terminals that lack ANSI
# ---------------------------------------------------------------------------
setup_colors() {
    BLUE=""
    GREEN=""
    YELLOW=""
    RED=""
    CYAN=""
    BOLD=""
    DIM=""
    RESET=""

    # Check if stdout is a terminal and supports color
    if [ -t 1 ]; then
        ncolors=$(tput colors 2>/dev/null || echo 0)
        if [ "${ncolors:-0}" -ge 8 ]; then
            BLUE='\033[94m'
            GREEN='\033[92m'
            YELLOW='\033[93m'
            RED='\033[91m'
            CYAN='\033[96m'
            BOLD='\033[1m'
            DIM='\033[2m'
            RESET='\033[0m'
        fi
    fi
}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
detect_os() {
    OS_TYPE="unknown"
    OS_LABEL="Unknown"

    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux*)
            # Distinguish native Linux from WSL
            if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
                OS_TYPE="wsl"
                OS_LABEL="Windows (WSL)"
            else
                OS_TYPE="linux"
                OS_LABEL="Linux"
            fi
            ;;
        Darwin*)
            OS_TYPE="macos"
            OS_LABEL="macOS"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS_TYPE="windows"
            OS_LABEL="Windows ($(uname -s | cut -d_ -f1))"
            ;;
        *)
            OS_TYPE="unknown"
            OS_LABEL="Unknown ($(uname -s 2>/dev/null || echo N/A))"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo -e "  ${CYAN}>${RESET} $*"; }
ok()      { echo -e "  ${GREEN}[ok]${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}[!!]${RESET} $*"; }
fail()    { echo -e "  ${RED}[ERR]${RESET} $*"; }
banner_line() { echo -e "  $*"; }

# Prompt helper — uses a default when input is empty
prompt_default() {
    local prompt_text="$1"
    local default_val="$2"
    local varname="$3"
    read -rp "$(echo -e "  ${BOLD}${prompt_text}${RESET} [${default_val}]: ")" _input
    eval "$varname=\"${_input:-$default_val}\""
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
show_banner() {
    echo ""
    echo -e "${BLUE}${BOLD}"
    banner_line "  ██████╗ ██╗      █████╗ ███████╗███████╗"
    banner_line "  ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝"
    banner_line "  ██████╔╝██║     ███████║  ███╔╝ █████╗  "
    banner_line "  ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝  "
    banner_line "  ██████╔╝███████╗██║  ██║███████╗███████╗"
    banner_line "  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝"
    echo -e "${RESET}"
    echo -e "    ${BOLD}Installer v2.3${RESET}  ${DIM}— cross-platform${RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# OS summary
# ---------------------------------------------------------------------------
show_os() {
    info "Detected platform: ${BOLD}${OS_LABEL}${RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# Python check — find python3/python >= 3.8
# ---------------------------------------------------------------------------
PYTHON=""

find_python() {
    local candidates="python3 python"
    # On Windows/MSYS, also try 'py' launcher
    if [ "$OS_TYPE" = "windows" ]; then
        candidates="python3 python py"
    fi

    for cmd in $candidates; do
        if command -v "$cmd" &>/dev/null; then
            local ver major minor
            ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null) || continue
            major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null) || continue
            minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null) || continue

            if [ "$major" -ge 3 ] 2>/dev/null && [ "$minor" -ge 8 ] 2>/dev/null; then
                PYTHON="$cmd"
                ok "Python ${ver} found  ${DIM}(${cmd})${RESET}"
                return 0
            else
                warn "Found ${cmd} ${ver} — too old (need 3.8+)"
            fi
        fi
    done

    fail "Python 3.8+ is required but was not found."
    echo ""
    case "$OS_TYPE" in
        linux|wsl)
            info "Install with your package manager, e.g.:"
            info "  sudo apt install python3        ${DIM}# Debian/Ubuntu${RESET}"
            info "  sudo dnf install python3         ${DIM}# Fedora${RESET}"
            ;;
        macos)
            info "Install via Homebrew:"
            info "  brew install python@3.12"
            ;;
        windows)
            info "Download from: https://www.python.org/downloads/"
            info "Or use:  winget install Python.Python.3.12"
            ;;
        *)
            info "Download from: https://www.python.org/downloads/"
            ;;
    esac
    echo ""
    exit 1
}

# ---------------------------------------------------------------------------
# Pip check
# ---------------------------------------------------------------------------
check_pip() {
    if "$PYTHON" -m pip --version &>/dev/null; then
        local pipver
        pipver=$("$PYTHON" -m pip --version 2>/dev/null | awk '{print $2}')
        ok "pip ${pipver} available"
    else
        warn "pip not found — attempting bootstrap..."
        "$PYTHON" -m ensurepip --default-pip 2>/dev/null || {
            fail "Could not install pip automatically."
            info "Manual fix:  $PYTHON -m ensurepip --upgrade"
            exit 1
        }
        ok "pip bootstrapped successfully"
    fi
}

# ---------------------------------------------------------------------------
# Installation menu
# ---------------------------------------------------------------------------
run_install() {
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    echo ""
    echo -e "  ${BOLD}Select installation method:${RESET}"
    echo ""
    echo -e "    ${BOLD}1)${RESET} pip install          ${DIM}(recommended — installs 'blaze' command)${RESET}"
    echo -e "    ${BOLD}2)${RESET} Standalone binary     ${DIM}(PyInstaller — single file, no deps)${RESET}"
    echo -e "    ${BOLD}3)${RESET} Development mode      ${DIM}(editable pip install for contributors)${RESET}"
    echo ""

    local choice
    prompt_default "Choice" "1" choice

    case "$choice" in
        1)
            echo ""
            info "Installing with pip..."
            "$PYTHON" -m pip install "$SCRIPT_DIR" --quiet --break-system-packages
            ok "Installed successfully."
            ;;
        2)
            echo ""
            info "Building standalone binary..."
            "$PYTHON" -m pip install pyinstaller --quiet --break-system-packages
            if [ -f "$SCRIPT_DIR/build.py" ]; then
                "$PYTHON" "$SCRIPT_DIR/build.py"
                ok "Build complete. Check the dist/ directory."
            else
                warn "build.py not found in ${SCRIPT_DIR}."
                fail "Cannot build standalone binary without build.py."
                exit 1
            fi
            ;;
        3)
            echo ""
            info "Installing in development (editable) mode..."
            "$PYTHON" -m pip install -e "$SCRIPT_DIR" --quiet --break-system-packages
            ok "Dev install complete."
            ;;
        *)
            echo ""
            fail "Invalid choice: ${choice}"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# uvloop — auto-install on Linux/macOS, skip on Windows
# ---------------------------------------------------------------------------
offer_uvloop() {
    echo ""

    if [ "$OS_TYPE" = "windows" ]; then
        info "Skipping uvloop ${DIM}(not supported on Windows)${RESET}"
        return 0
    fi

    info "Installing uvloop for faster async I/O..."
    "$PYTHON" -m pip install "blaze-scanner[fast]" --quiet --break-system-packages 2>/dev/null || \
    "$PYTHON" -m pip install uvloop --quiet --break-system-packages 2>/dev/null || true
    ok "uvloop installed"
}

# ---------------------------------------------------------------------------
# Usage examples
# ---------------------------------------------------------------------------
show_usage() {
    echo ""
    echo -e "  ${GREEN}${BOLD}Installation complete!${RESET}"
    echo ""
    echo -e "  ${BOLD}Usage examples:${RESET}"
    echo ""
    echo -e "    ${CYAN}blaze -u https://target.com${RESET}                Smart scan"
    echo -e "    ${CYAN}blaze -u https://target.com -r --depth 5${RESET}   Recursive crawl"
    echo -e "    ${CYAN}blaze -u https://target.com -t 200${RESET}         200 threads"
    echo -e "    ${CYAN}blaze --help${RESET}                               All options"
    echo ""
    echo -e "  ${DIM}Docs & issues: https://github.com/blaze-scanner/blaze${RESET}"
    echo ""
}

# ============================= MAIN ========================================
main() {
    setup_colors
    show_banner
    detect_os
    show_os
    find_python
    check_pip
    run_install
    offer_uvloop
    show_usage
}

main "$@"
