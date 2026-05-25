#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Suricata IDS — installed here rather than in the Dockerfile because it
# requires an external repository (OISF PPA on Ubuntu; OISF OBS on Debian).
# The devcontainer targets Debian 12 arm64, which OISF only provides via
# the OBS x86-64 repo; on arm64 the install is skipped with a clear warning.
# Suricata is fully functional on the production SIFT workstation (Ubuntu
# 24.04 x86-64) where the OISF PPA covers it.
# ---------------------------------------------------------------------------
if command -v suricata &>/dev/null; then
    echo "[devcontainer] Suricata already installed: $(suricata --version 2>&1 | head -1)"
else
    ARCH="$(dpkg --print-architecture)"
    OS_ID="$(. /etc/os-release && echo "$ID")"

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "[devcontainer] Installing Suricata via OISF PPA (Ubuntu)"
        sudo apt-get install -y --no-install-recommends software-properties-common 2>/dev/null
        sudo add-apt-repository -y ppa:oisf/suricata-stable
        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends suricata \
            && echo "[devcontainer] Suricata $(suricata --version 2>&1 | head -1) installed" \
            || echo "[devcontainer] Warning: Suricata PPA install failed"
    elif [[ "$ARCH" == "amd64" || "$ARCH" == "x86_64" ]]; then
        echo "[devcontainer] Installing Suricata via OISF OBS repo (Debian x86-64)"
        CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
        OBS_CODENAME="Debian_$(. /etc/os-release && echo "$VERSION_ID")"
        SURICATA_REPO="https://download.opensuse.org/repositories/security:/ids:/suricata/${OBS_CODENAME}/"
        SURICATA_KEY_URL="${SURICATA_REPO}Release.key"
        curl -fsSL "$SURICATA_KEY_URL" \
            | gpg --dearmor \
            | sudo tee /etc/apt/trusted.gpg.d/suricata-oisf.gpg > /dev/null \
            && echo "deb [signed-by=/etc/apt/trusted.gpg.d/suricata-oisf.gpg] ${SURICATA_REPO} /" \
                | sudo tee /etc/apt/sources.list.d/suricata-oisf.list > /dev/null \
            && sudo apt-get update -qq \
            && sudo apt-get install -y --no-install-recommends suricata \
            && echo "[devcontainer] Suricata $(suricata --version 2>&1 | head -1) installed" \
            || echo "[devcontainer] Warning: Suricata OBS install failed — IDS features unavailable"
    else
        echo "[devcontainer] Warning: Suricata has no pre-built packages for ${OS_ID}/${ARCH}."
        echo "[devcontainer]   IDS analysis will be unavailable in this devcontainer."
        echo "[devcontainer]   Suricata is fully supported on the production SIFT workstation (Ubuntu 24.04 x86-64)."
    fi
fi

echo "[devcontainer] Upgrading pip"
python -m pip install --upgrade pip

# graphifyy is currently not on PyPI; skip it so container setup can complete.
if grep -qE '^graphifyy([<>=].*)?$' requirements.txt; then
  echo "[devcontainer] Installing Python requirements (excluding graphifyy, unavailable on PyPI)"
  grep -vE '^graphifyy([<>=].*)?$' requirements.txt > /tmp/requirements.devcontainer.txt
  python -m pip install -r /tmp/requirements.devcontainer.txt
else
  echo "[devcontainer] Installing Python requirements"
  python -m pip install -r requirements.txt
fi

if command -v npm >/dev/null 2>&1; then
  echo "[devcontainer] Installing Claude Code CLI"
  NPM_GLOBAL_PREFIX="$HOME/.npm-global"
  mkdir -p "$NPM_GLOBAL_PREFIX"
  npm config set prefix "$NPM_GLOBAL_PREFIX"

  # Ensure the CLI binary is discoverable in both this run and future shells.
  export PATH="$NPM_GLOBAL_PREFIX/bin:$PATH"
  if ! grep -q 'npm-global/bin' "$HOME/.bashrc" 2>/dev/null; then
    printf '\nexport PATH="$HOME/.npm-global/bin:$PATH"\n' >> "$HOME/.bashrc"
  fi

  npm install -g @anthropic-ai/claude-code || echo "[devcontainer] Warning: Claude Code CLI install failed"
else
  echo "[devcontainer] Warning: npm is not available; skipping Claude Code CLI install"
fi

echo "[devcontainer] Setup complete"
