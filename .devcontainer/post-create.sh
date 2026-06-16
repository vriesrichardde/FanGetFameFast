#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Suricata IDS — not in Debian Bookworm apt; installed via:
#   Ubuntu        → OISF PPA (pre-built)
#   Debian amd64  → OISF OBS repo (pre-built)
#   Debian arm64  → build from source (OISF provides no arm64 Debian package;
#                   source build is architecture-agnostic and verified working)
# ---------------------------------------------------------------------------
_install_suricata_from_source() {
    local version="7.0.10"
    local tmp; tmp="$(mktemp -d)"
    echo "[devcontainer] Building Suricata ${version} from source (this takes ~5 min)..."
    curl -fsSL "https://www.openinfosecfoundation.org/download/suricata-${version}.tar.gz" \
        -o "${tmp}/suricata.tar.gz" || { echo "[devcontainer] Warning: Suricata download failed"; rm -rf "$tmp"; return 1; }
    tar -xzf "${tmp}/suricata.tar.gz" -C "$tmp"
    cd "${tmp}/suricata-${version}"
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --disable-gccmarch-native --quiet \
        && make -j"$(nproc)" \
        && sudo make install \
        && sudo make install-conf \
        && echo "[devcontainer] Suricata ${version} installed (source build)" \
        || echo "[devcontainer] Warning: Suricata source build failed — IDS features unavailable"
    rm -rf "$tmp"
    cd /workspaces/FanGetFameFast
}

if command -v suricata &>/dev/null; then
    echo "[devcontainer] Suricata already installed: $(suricata --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
else
    ARCH="$(dpkg --print-architecture)"
    OS_ID="$(. /etc/os-release && echo "$ID")"

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "[devcontainer] Installing Suricata via OISF PPA (Ubuntu)"
        sudo apt-get install -y --no-install-recommends software-properties-common 2>/dev/null
        sudo add-apt-repository -y ppa:oisf/suricata-stable
        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends suricata \
            && echo "[devcontainer] Suricata installed" \
            || _install_suricata_from_source
    elif [[ "$ARCH" == "amd64" ]]; then
        echo "[devcontainer] Installing Suricata via OISF OBS repo (Debian amd64)"
        OBS_CODENAME="Debian_$(. /etc/os-release && echo "$VERSION_ID")"
        SURICATA_REPO="https://download.opensuse.org/repositories/security:/ids:/suricata/${OBS_CODENAME}/"
        curl -fsSL "${SURICATA_REPO}Release.key" \
            | gpg --dearmor \
            | sudo tee /etc/apt/trusted.gpg.d/suricata-oisf.gpg > /dev/null \
            && echo "deb [signed-by=/etc/apt/trusted.gpg.d/suricata-oisf.gpg] ${SURICATA_REPO} /" \
                | sudo tee /etc/apt/sources.list.d/suricata-oisf.list > /dev/null \
            && sudo apt-get update -qq \
            && sudo apt-get install -y --no-install-recommends suricata \
            && echo "[devcontainer] Suricata installed" \
            || _install_suricata_from_source
    else
        # arm64 (and any other arch): build from source — verified working on arm64/Debian 12
        _install_suricata_from_source
    fi
fi

# ---------------------------------------------------------------------------
# bulk_extractor — not in Debian Bookworm apt; build from source.
# Verified working on arm64 (requires libre2-dev, included in Dockerfile).
# Fallback carvers foremost / scalpel / binwalk are installed via apt
# and available on all architectures.
# ---------------------------------------------------------------------------
if command -v bulk_extractor &>/dev/null; then
    echo "[devcontainer] bulk_extractor already installed: $(bulk_extractor --version 2>&1 | head -1)"
else
    echo "[devcontainer] Building bulk_extractor from source (verified on amd64 + arm64)..."
    BE_TMP="$(mktemp -d)"
    BE_VERSION="2.1.1"
    curl -fsSL "https://github.com/simsong/bulk_extractor/releases/download/v${BE_VERSION}/bulk_extractor-${BE_VERSION}.tar.gz" \
        -o "${BE_TMP}/bulk_extractor.tar.gz" \
        && tar -xzf "${BE_TMP}/bulk_extractor.tar.gz" -C "$BE_TMP" \
        && cd "${BE_TMP}/bulk_extractor-${BE_VERSION}" \
        && ./configure --prefix=/usr/local --quiet \
        && make -j"$(nproc)" \
        && sudo make install \
        && echo "[devcontainer] bulk_extractor $(bulk_extractor --version 2>&1 | head -1) installed" \
        || echo "[devcontainer] Warning: bulk_extractor build failed — use foremost/scalpel/binwalk for file carving"
    rm -rf "$BE_TMP"
    cd /workspaces/FanGetFameFast
fi

# ---------------------------------------------------------------------------
# SiLK + YAF — not in Debian Bookworm apt; built from source per:
#   https://tools.netsa.cert.org/silk/silk-on-box-deb.html
# Build order: libfixbuf → SiLK → YAF
# ---------------------------------------------------------------------------

# SHA-256 digests from the official CERT/NetSA download pages:
#   https://tools.netsa.cert.org/fixbuf2/download.html
#   https://tools.netsa.cert.org/silk/download.html
#   https://tools.netsa.cert.org/yaf2/download.html
# Update these whenever the pinned versions above change.
_FIXBUF_SHA256="106b8e1e560928a4dc91d8264326bd2463767570d77417535964f450de1f972e"
_SILK_SHA256="9ea9c1391f9c1ba14394af68b2bd7e66bf73b664c3cee342c5a39e5b13e45398"
_YAF_SHA256="6b03bc3d25495c01d8d8020b00a908ef1ed28b6edf78f631618208d81e809b30"

_verify_sha256() {
    local file="$1" expected="$2" label="$3"
    local actual
    actual="$(sha256sum "$file" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        echo "[devcontainer] ERROR: SHA-256 mismatch for ${label}" >&2
        echo "[devcontainer]   expected: ${expected}" >&2
        echo "[devcontainer]   got:      ${actual}" >&2
        return 1
    fi
    echo "[devcontainer] SHA-256 verified: ${label}"
}

_install_silk_yaf_from_source() {
    local FIXBUF_VERSION="2.5.4"
    local SILK_VERSION="3.24.2"
    local YAF_VERSION="2.19.3"
    local BASE_URL="https://tools.netsa.cert.org/releases"
    local tmp; tmp="$(mktemp -d)"

    echo "[devcontainer] Building libfixbuf ${FIXBUF_VERSION} from source..."
    curl -fsSL "${BASE_URL}/libfixbuf-${FIXBUF_VERSION}.tar.gz" \
        -o "${tmp}/libfixbuf.tar.gz" \
        || { echo "[devcontainer] Warning: libfixbuf download failed"; rm -rf "$tmp"; return 1; }
    _verify_sha256 "${tmp}/libfixbuf.tar.gz" "$_FIXBUF_SHA256" "libfixbuf-${FIXBUF_VERSION}.tar.gz" \
        || { rm -rf "$tmp"; return 1; }
    tar -zxf "${tmp}/libfixbuf.tar.gz" -C "$tmp"
    cd "${tmp}/libfixbuf-${FIXBUF_VERSION}"
    ./configure --prefix=/usr/local --enable-silent-rules \
        && make -j"$(nproc)" \
        && sudo make install \
        && echo "[devcontainer] libfixbuf ${FIXBUF_VERSION} installed" \
        || { echo "[devcontainer] Warning: libfixbuf build failed — skipping SiLK + YAF"; rm -rf "$tmp"; return 1; }

    echo "[devcontainer] Building SiLK ${SILK_VERSION} from source..."
    curl -fsSL "${BASE_URL}/silk-${SILK_VERSION}.tar.gz" \
        -o "${tmp}/silk.tar.gz" \
        || { echo "[devcontainer] Warning: SiLK download failed"; rm -rf "$tmp"; return 1; }
    _verify_sha256 "${tmp}/silk.tar.gz" "$_SILK_SHA256" "silk-${SILK_VERSION}.tar.gz" \
        || { rm -rf "$tmp"; return 1; }
    tar -zxf "${tmp}/silk.tar.gz" -C "$tmp"
    cd "${tmp}/silk-${SILK_VERSION}"
    ./configure \
            --prefix=/usr/local \
            --enable-silent-rules \
            --enable-data-rootdir=/var/silk/data \
            --enable-ipv6 \
            --enable-ipset-compatibility=3.14.0 \
            --enable-output-compression \
            --with-python \
            --with-python-prefix \
        && make -j"$(nproc)" \
        && sudo make install \
        && echo "[devcontainer] SiLK ${SILK_VERSION} installed" \
        || { echo "[devcontainer] Warning: SiLK build failed"; rm -rf "$tmp"; return 1; }

    echo "[devcontainer] Building YAF ${YAF_VERSION} from source..."
    curl -fsSL "${BASE_URL}/yaf-${YAF_VERSION}.tar.gz" \
        -o "${tmp}/yaf.tar.gz" \
        || { echo "[devcontainer] Warning: YAF download failed"; rm -rf "$tmp"; return 1; }
    _verify_sha256 "${tmp}/yaf.tar.gz" "$_YAF_SHA256" "yaf-${YAF_VERSION}.tar.gz" \
        || { rm -rf "$tmp"; return 1; }
    tar -zxf "${tmp}/yaf.tar.gz" -C "$tmp"
    cd "${tmp}/yaf-${YAF_VERSION}"
    ./configure \
            --prefix=/usr/local \
            --enable-silent-rules \
            --enable-applabel \
            --enable-metadata \
            --enable-plugins \
        && make -j"$(nproc)" \
        && sudo make install \
        && echo "[devcontainer] YAF ${YAF_VERSION} installed" \
        || echo "[devcontainer] Warning: YAF build failed — YAF features unavailable"

    # Update the dynamic linker cache so /usr/local/lib is found at runtime.
    if ! grep -qr '/usr/local/lib' /etc/ld.so.conf.d/ 2>/dev/null; then
        echo '/usr/local/lib' | sudo tee /etc/ld.so.conf.d/silk.conf > /dev/null
    fi
    sudo ldconfig

    rm -rf "$tmp"
    cd /workspaces/FanGetFameFast
}

if command -v rwfilter &>/dev/null && command -v yaf &>/dev/null; then
    echo "[devcontainer] SiLK/YAF already installed: rwfilter $(rwfilter --version 2>&1 | head -1), yaf $(yaf --version 2>&1 | head -1)"
else
    _install_silk_yaf_from_source
fi

echo "[devcontainer] Upgrading pip"
python -m pip install --upgrade pip

# memprocfs is x86-64 only — skip it on arm64 so container setup completes cleanly.
ARCH="$(dpkg --print-architecture)"
if [[ "$ARCH" != "amd64" ]]; then
  SKIP_PATTERN='^memprocfs([<>=!~].*)?$'
  echo "[devcontainer] Installing Python requirements (excluding x86-64-only packages for ${ARCH})"
  grep -vE "$SKIP_PATTERN" requirements.txt > /tmp/requirements.devcontainer.txt
  python -m pip install -r /tmp/requirements.devcontainer.txt
else
  echo "[devcontainer] Installing Python requirements"
  python -m pip install -r requirements.txt
fi

# ---------------------------------------------------------------------------
# Volatility 3 — memory forensics framework (FAME module).
# Installed via requirements.txt above; verify the entry-point is available.
# ---------------------------------------------------------------------------
if python -c "import volatility3" &>/dev/null && command -v vol &>/dev/null; then
    VOL_VER="$(vol -h 2>&1 | grep -oE 'Volatility [0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    echo "[devcontainer] ${VOL_VER:-Volatility 3} installed (vol entry-point available)"
else
    echo "[devcontainer] Installing Volatility 3 explicitly..."
    python -m pip install --quiet "volatility3>=2.0.0" \
        && echo "[devcontainer] Volatility 3 $(python -c 'import volatility3; print(volatility3.__version__)') installed" \
        || echo "[devcontainer] Warning: Volatility 3 install failed — FAME module may not function"
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
