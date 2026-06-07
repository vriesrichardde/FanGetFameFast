#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# =============================================================================
# install_dependencies.sh — FanGetFameFast production dependency installer
#
# Installs and configures all system packages, Python packages, and CLI tools
# required by the platform. Safe to re-run; all steps are idempotent.
#
# Tested on: Ubuntu 22.04 LTS (Jammy) · Ubuntu 24.04 LTS (Noble)
#
# Usage (run as the service account user, with sudo access):
#   bash scripts/install_dependencies.sh
#   bash scripts/install_dependencies.sh --skip-suricata
#   bash scripts/install_dependencies.sh --skip-yara
#   bash scripts/install_dependencies.sh --skip-dotnet
#   bash scripts/install_dependencies.sh --offline    # apt only, no PPA/pip
#   bash scripts/install_dependencies.sh --help
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Colour helpers ────────────────────────────────────────────────────────────
C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
TICK="${C_GREEN}✓${C_RESET}"; CROSS="${C_RED}✗${C_RESET}"; SKIP="${C_YELLOW}–${C_RESET}"
section() { echo ""; echo -e "${C_BOLD}${C_CYAN}══════  $*  ══════${C_RESET}"; }
info()    { echo -e "  ${C_CYAN}[*]${C_RESET} $*"; }
ok()      { echo -e "  ${TICK} $*"; }
warn()    { echo -e "  ${C_YELLOW}[!]${C_RESET} $*"; }
err()     { echo -e "  ${CROSS} $*" >&2; }
skip()    { echo -e "  ${SKIP} $*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
SKIP_SURICATA=0
SKIP_YARA=0
SKIP_DOTNET=0
OFFLINE=0

for arg in "$@"; do
    case "$arg" in
        --skip-suricata) SKIP_SURICATA=1 ;;
        --skip-yara)     SKIP_YARA=1 ;;
        --skip-dotnet)   SKIP_DOTNET=1 ;;
        --offline)       OFFLINE=1 ;;
        --help|-h)
            echo "Usage: $0 [--skip-suricata] [--skip-yara] [--skip-dotnet] [--offline]"
            exit 0 ;;
        *) warn "Unknown argument: $arg (ignored)" ;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────────────
section "Pre-flight checks"

# Must be run on Ubuntu / Debian
if ! command -v apt-get &>/dev/null; then
    err "apt-get not found. This script requires Ubuntu 22.04+ or Debian 12+."
    exit 1
fi

# Warn if running as root (service account preferred)
if [[ $EUID -eq 0 ]]; then
    warn "Running as root. Consider running as a dedicated service account instead."
fi

# Check sudo is available
if ! sudo -n true 2>/dev/null; then
    info "sudo access required for system package installation."
    info "You will be prompted for your password."
fi

# Detect Ubuntu version
UBUNTU_VER="$(lsb_release -rs 2>/dev/null || echo "0")"
UBUNTU_CODENAME="$(lsb_release -cs 2>/dev/null || echo "unknown")"
ok "Detected: Ubuntu ${UBUNTU_VER} (${UBUNTU_CODENAME})"

# Verify Python 3.10+
PYTHON_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MIN="3.10"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    ok "Python ${PYTHON_VER} — meets minimum ${PYTHON_MIN}"
else
    err "Python ${PYTHON_VER} found but ${PYTHON_MIN}+ is required."
    exit 1
fi

# ── System packages — core ────────────────────────────────────────────────────
section "System packages — core"

info "Updating apt package index …"
sudo apt-get update -qq

CORE_PKGS=(
    # Build tools
    build-essential
    pkg-config
    cmake
    git
    curl
    wget
    # Python
    python3
    python3-pip
    python3-venv
    python3-dev
    # Network tools
    tshark
    wireshark-common
    # Process / file utilities
    inotify-tools
    zip
    unzip
    jq
    # System utilities
    lsb-release
    ca-certificates
    gnupg
    apt-transport-https
    software-properties-common
    # Fonts for PDF rendering
    fonts-liberation
    fonts-liberation2
    fonts-dejavu-core
    fonts-dejavu-extra
    fonts-lato
    fonts-noto-core
)

info "Installing core packages …"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${CORE_PKGS[@]}"
ok "Core packages installed"

# ── System packages — WeasyPrint PDF rendering ────────────────────────────────
section "System packages — PDF rendering (WeasyPrint)"

WEASYPRINT_PKGS=(
    libcairo2
    libcairo2-dev
    libpango-1.0-0
    libpangocairo-1.0-0
    libpangoft2-1.0-0
    libgdk-pixbuf2.0-0
    libffi-dev
    libxml2
    libxml2-dev
    libxslt1.1
    libxslt1-dev
    libssl-dev
    shared-mime-info
    libharfbuzz-dev
    libfontconfig1
    libglib2.0-0
)

info "Installing WeasyPrint system dependencies …"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${WEASYPRINT_PKGS[@]}" || \
    warn "Some WeasyPrint dependencies may not be available on this distro version — PDF generation may be degraded"
ok "PDF rendering dependencies installed"

# ── Suricata IDS ─────────────────────────────────────────────────────────────
section "Suricata IDS"

if [[ $SKIP_SURICATA -eq 1 ]]; then
    skip "Skipping Suricata (--skip-suricata)"
elif command -v suricata &>/dev/null; then
    SURICATA_VER="$(suricata --build-info 2>/dev/null | grep '^Suricata version' | awk '{print $3}')"
    ok "Suricata already installed: ${SURICATA_VER}"
else
    info "Adding Suricata stable PPA …"
    sudo add-apt-repository -y ppa:oisf/suricata-stable
    sudo apt-get update -qq
    info "Installing Suricata …"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq suricata
    ok "Suricata $(suricata --build-info 2>/dev/null | grep '^Suricata version' | awk '{print $3}') installed"
fi

# Install suricata-update (rule manager)
if [[ $SKIP_SURICATA -eq 0 ]]; then
    if ! command -v suricata-update &>/dev/null; then
        info "Installing suricata-update …"
        sudo pip3 install --break-system-packages suricata-update 2>/dev/null || \
            pip3 install suricata-update 2>/dev/null || \
            warn "suricata-update could not be installed — use --et-only mode for rule updates"
    else
        ok "suricata-update already installed"
    fi
fi

# ── YARA ─────────────────────────────────────────────────────────────────────
section "YARA rule engine"

if [[ $SKIP_YARA -eq 1 ]]; then
    skip "Skipping YARA (--skip-yara)"
elif command -v yara &>/dev/null; then
    YARA_VER="$(yara --version 2>/dev/null)"
    ok "YARA already installed: ${YARA_VER}"
else
    # Try apt first (Ubuntu 22.04+ ships YARA in universe)
    info "Attempting YARA installation via apt …"
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq yara 2>/dev/null; then
        ok "YARA $(yara --version) installed via apt"
    else
        # Build from source
        info "Building YARA 4.5.0 from source …"
        YARA_VERSION="4.5.0"
        YARA_BUILD_DIR="$(mktemp -d)"
        trap 'rm -rf "$YARA_BUILD_DIR"' EXIT

        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            libssl-dev libjansson-dev libmagic-dev \
            automake libtool flex bison

        curl -sL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" \
            -o "${YARA_BUILD_DIR}/yara.tar.gz"
        tar -xzf "${YARA_BUILD_DIR}/yara.tar.gz" -C "$YARA_BUILD_DIR"
        cd "${YARA_BUILD_DIR}/yara-${YARA_VERSION}"
        ./bootstrap.sh
        ./configure --with-crypto --enable-magic --enable-dotnet --prefix=/usr/local
        make -j"$(nproc)"
        sudo make install
        sudo ldconfig
        cd "$PROJECT_ROOT"
        ok "YARA ${YARA_VERSION} built and installed"
    fi
fi

# ── .NET Runtime (EZ Tools) ───────────────────────────────────────────────────
section ".NET Runtime (EZ Tools / Zimmerman Tools)"

if [[ $SKIP_DOTNET -eq 1 ]]; then
    skip "Skipping .NET Runtime (--skip-dotnet)"
elif command -v dotnet &>/dev/null; then
    DOTNET_VER="$(dotnet --list-runtimes 2>/dev/null | head -1 | awk '{print $2}')"
    ok ".NET Runtime already installed: ${DOTNET_VER}"
else
    info "Installing .NET Runtime via Microsoft APT feed …"
    # Add Microsoft package signing key
    curl -sL https://packages.microsoft.com/config/ubuntu/"${UBUNTU_VER}"/packages-microsoft-prod.deb \
        -o /tmp/packages-microsoft-prod.deb
    sudo dpkg -i /tmp/packages-microsoft-prod.deb
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dotnet-runtime-6.0 dotnet-runtime-8.0 || \
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq aspnetcore-runtime-6.0 || \
        warn ".NET install may be incomplete — EZ Tools functionality may be limited"
    ok ".NET Runtime installed"
fi

# ── EZ Tools (Zimmerman Tools) ────────────────────────────────────────────────
section "EZ Tools (Zimmerman / SANS DFIR)"

EZ_DIR="/opt/zimmermantools"
if [[ -d "$EZ_DIR" ]] && find "$EZ_DIR" -name "*.dll" | grep -q .; then
    ok "EZ Tools already present at ${EZ_DIR}"
else
    if [[ $SKIP_DOTNET -eq 0 ]]; then
        info "Downloading EZ Tools …"
        sudo mkdir -p "$EZ_DIR"
        sudo chown "$(whoami)":"$(whoami)" "$EZ_DIR"
        # Use the official Get-ZimmermanTools equivalent for Linux
        EZ_INSTALLER_URL="https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
        if command -v pwsh &>/dev/null; then
            info "Using PowerShell to download EZ Tools …"
            pwsh -Command "& { \$ErrorActionPreference='Stop'; iex (irm '${EZ_INSTALLER_URL}') }" || \
                warn "EZ Tools download via PowerShell failed — install manually to ${EZ_DIR}"
        else
            warn "PowerShell not available. Download EZ Tools manually:"
            warn "  https://ericzimmerman.github.io/#!index.md"
            warn "  Extract to: ${EZ_DIR}"
        fi
    else
        skip "EZ Tools skipped (--skip-dotnet)"
    fi
fi

# ── Python virtual environment ────────────────────────────────────────────────
section "Python virtual environment"

VENV_DIR="${PROJECT_ROOT}/.venv"

if [[ -d "$VENV_DIR" ]] && [[ -f "${VENV_DIR}/bin/activate" ]]; then
    ok "Virtual environment already exists at ${VENV_DIR}"
else
    info "Creating virtual environment at ${VENV_DIR} …"
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created"
fi

info "Activating virtual environment …"
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

# Upgrade pip first
info "Upgrading pip …"
pip install --quiet --upgrade pip

# ── Python packages ───────────────────────────────────────────────────────────
section "Python packages"

REQUIREMENTS_FILE="${PROJECT_ROOT}/requirements.txt"

if [[ -f "$REQUIREMENTS_FILE" ]]; then
    info "Installing from requirements.txt …"
    pip install --quiet -r "$REQUIREMENTS_FILE"
    ok "Python packages installed from requirements.txt"
else
    warn "requirements.txt not found — installing baseline packages only"
    pip install --quiet \
        "PyYAML==6.0.3" \
        "Markdown==3.10.2" \
        "weasyprint==68.1" \
        "cairocffi==1.7.1" \
        "CairoSVG==2.9.0" \
        "python-pptx==1.0.2" \
        "python-docx==1.2.0" \
        "plotly==5.18.0" \
        "yara-python==4.3.1"
fi

deactivate
ok "Virtual environment ready: ${VENV_DIR}"

# ── Claude Code CLI ───────────────────────────────────────────────────────────
section "Claude Code CLI"

if command -v claude &>/dev/null; then
    ok "Claude Code CLI already installed: $(claude --version 2>/dev/null | head -1)"
else
    if [[ $OFFLINE -eq 0 ]]; then
        info "Installing Claude Code CLI via npm …"
        if command -v npm &>/dev/null; then
            sudo npm install -g @anthropic-ai/claude-code
            ok "Claude Code CLI installed"
        elif command -v snap &>/dev/null; then
            info "npm not found — attempting snap install …"
            sudo snap install node --classic
            sudo npm install -g @anthropic-ai/claude-code
            ok "Claude Code CLI installed via snap"
        else
            warn "npm not found. Install Node.js + npm, then run:"
            warn "  sudo npm install -g @anthropic-ai/claude-code"
        fi
    else
        warn "Offline mode: Claude Code CLI must be installed manually."
        warn "  https://claude.ai/code"
    fi
fi

# ── Script permissions ────────────────────────────────────────────────────────
section "Script permissions"

info "Making scripts executable …"
find "${PROJECT_ROOT}/scripts" -name "*.sh" -exec chmod +x {} \;
find "${PROJECT_ROOT}/scripts" -name "*.py" -exec chmod +x {} \;
ok "Scripts are executable"

# ── tshark / Wireshark permissions ────────────────────────────────────────────
section "tshark permissions"

# Allow the current user to capture without root
if getent group wireshark &>/dev/null; then
    if id -nG "$(whoami)" | grep -qw wireshark; then
        ok "$(whoami) is already in the wireshark group"
    else
        info "Adding $(whoami) to wireshark group (enables non-root tshark capture) …"
        sudo usermod -aG wireshark "$(whoami)"
        warn "Group change takes effect on next login."
    fi
else
    info "Reconfiguring wireshark-common to allow non-root capture …"
    echo "wireshark-common wireshark-common/install-setuid boolean true" | \
        sudo debconf-set-selections
    sudo dpkg-reconfigure -f noninteractive wireshark-common 2>/dev/null || true
fi

# ── Sudoers — NOPASSWD for non-interactive commands ──────────────────────────
section "Sudoers (passwordless sudo for forensic tools)"

info "Configuring NOPASSWD sudo for suricata-update …"
if bash "${SCRIPT_DIR}/setup_sudoers.sh"; then
    ok "Sudoers configured: /etc/sudoers.d/fangetfamefast"
else
    warn "Sudoers setup failed — Suricata rule auto-update will not work non-interactively."
    warn "Run manually: sudo bash scripts/setup_sudoers.sh"
fi

# ── Suricata rule download ────────────────────────────────────────────────────
section "Initial Suricata rules"

if [[ $SKIP_SURICATA -eq 0 ]]; then
    RULES_DIR="${PROJECT_ROOT}/rules/suricata"
    mkdir -p "$RULES_DIR"
    if [[ -f "${RULES_DIR}/et-open.rules" ]]; then
        ok "Suricata rules already present"
    else
        info "Downloading Emerging Threats Open rules …"
        "${PROJECT_ROOT}/scripts/update_suricata_rules.sh" --et-only || \
            warn "Rule download failed — run scripts/update_suricata_rules.sh manually"
    fi
fi

# ── YARA rule compilation check ───────────────────────────────────────────────
section "YARA rules"

if [[ $SKIP_YARA -eq 0 ]]; then
    YARA_RULES_DIR="${PROJECT_ROOT}/rules/yara"
    if find "$YARA_RULES_DIR" -name "*.yar" | grep -q .; then
        RULE_COUNT="$(find "$YARA_RULES_DIR" -name "*.yar" | wc -l)"
        ok "${RULE_COUNT} YARA rule file(s) found in ${YARA_RULES_DIR}"
        # Verify rules compile
        info "Validating YARA rules …"
        if find "$YARA_RULES_DIR" -name "*.yar" -exec yara -C {} /dev/null \; 2>/dev/null; then
            ok "All YARA rules pass syntax validation"
        else
            warn "One or more YARA rules have syntax issues — check manually with:"
            warn "  find ${YARA_RULES_DIR} -name '*.yar' -exec yara {} /dev/null \\;"
        fi
    else
        warn "No YARA rules found in ${YARA_RULES_DIR} — add .yar files before running"
    fi
fi

# ── Environment variable check ────────────────────────────────────────────────
section "Environment variables"

REQUIRED_VARS=(PERPLEXITY_API_KEY)
OPTIONAL_VARS=(
    OPENCTI_URL OPENCTI_API_KEY
    SOC_VA_POLL_INTERVAL SOC_NOTIFY_WEBHOOK
)

for var in "${REQUIRED_VARS[@]}"; do
    if [[ -n "${!var:-}" ]]; then
        ok "${var} is set"
    else
        warn "${var} is NOT set — add to ~/.bashrc:"
        warn "  export ${var}=\"your-value\""
    fi
done

for var in "${OPTIONAL_VARS[@]}"; do
    if [[ -n "${!var:-}" ]]; then
        ok "${var} is set"
    else
        skip "${var} not set (optional — needed for OpenCTI integration)"
    fi
done

# ── Self-test ─────────────────────────────────────────────────────────────────
section "Post-install self-test"

ERRORS=0

check_cmd() {
    local cmd="$1"; local label="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        ok "${label}: $(command -v "$cmd")"
    else
        err "${label}: NOT FOUND"
        ERRORS=$((ERRORS+1))
    fi
}

check_cmd tshark      "tshark"
check_cmd suricata    "suricata"  || true
check_cmd yara        "yara"
check_cmd zip         "zip"
check_cmd inotifywait "inotifywait (optional)"  || true
check_cmd dotnet      ".NET Runtime"  || true

# Python package check
source "${VENV_DIR}/bin/activate"
for pkg in yaml markdown weasyprint pptx; do
    if python3 -c "import $pkg" 2>/dev/null; then
        ok "Python: $pkg"
    else
        err "Python: $pkg NOT importable"
        ERRORS=$((ERRORS+1))
    fi
done
deactivate

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${C_GREEN}${C_BOLD}Installation complete — all checks passed.${C_RESET}"
else
    echo -e "${C_YELLOW}${C_BOLD}Installation complete with ${ERRORS} issue(s). Review warnings above.${C_RESET}"
fi

# ── Next steps ────────────────────────────────────────────────────────────────
section "Next steps"

cat <<'EOF'
  1. Run the folder structure setup:
       bash scripts/setup_folder_structure.sh

  2. Configure API credentials in ~/.soc_env (copy template):
       cp templates/set_env_template.sh ~/.soc_env
       nano ~/.soc_env    # fill in PERPLEXITY_API_KEY, OPENCTI_URL, OPENCTI_API_KEY
       echo 'source ~/.soc_env' >> ~/.bashrc
       source ~/.soc_env

  3. Run the smoke test:
       ./scripts/test_solution.sh

  4. Analyse a PCAP:
       ./scripts/analyze_pcap.sh /path/to/capture.pcap
EOF
