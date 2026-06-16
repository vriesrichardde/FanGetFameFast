# SIFT Workstation edition (arm64) — installs SANS SIFT via `cast install`
# (https://www.sans.org/tools/sift-workstation, Option 2a) on top of the same
# Ubuntu base, then layers on tools known not to be covered by SIFT's
# saltstack states for this architecture.
#
# Base image must be Ubuntu (cast/teamdfir's saltstack states target
# Ubuntu 20.04/22.04), unlike the Debian-based default `.devcontainer/Dockerfile`.
FROM mcr.microsoft.com/devcontainers/base:ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# Prevent interactive wireshark/tshark package configuration during image build.
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections

# ---------------------------------------------------------------------------
# Base toolset (apt) — same coverage as `.devcontainer/Dockerfile`, kept as a
# safety net for anything `cast install` below doesn't provide on arm64.
# Trim duplicates once a build confirms SIFT's saltstack states already
# install the equivalent tool.
# ---------------------------------------------------------------------------
# Node.js 18.x via NodeSource — Ubuntu 22.04 default apt ships v12 which is too old for Claude Code (requires >=18).
# NodeSource's nodejs package bundles npm, so do NOT also install the Ubuntu npm package (they conflict).
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

RUN rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        # Python (base:ubuntu22.04 has no Python by default)
        python3 \
        python3-pip \
        python3-venv \
        # Build tools
        build-essential \
        cmake \
        pkg-config \
        curl \
        wget \
        git \
        gpg \
        # Node.js 18 (Claude Code CLI) — npm is bundled by NodeSource, not installed separately
        nodejs \
        # Network forensics
        tshark \
        wireshark-common \
        # silk-tools and yaf are not available in Ubuntu 22.04 apt; built from
        # source in post-create.sh per https://tools.netsa.cert.org/silk/silk-on-box-deb.html
        # Build deps for libfixbuf → SiLK → YAF source builds:
        libglib2.0-dev \
        liblzo2-dev \
        zlib1g-dev \
        libgnutls28-dev \
        libmaxminddb-dev \
        # File / process utilities
        inotify-tools \
        jq \
        ripgrep \
        unzip \
        zip \
        # YARA rule engine
        yara \
        # Suricata rule manager (suricata itself is installed via post-create.sh)
        suricata-update \
        # The Sleuth Kit — disk image analysis (FAST module)
        sleuthkit \
        autopsy \
        # EWF (EnCase) image tools (FAST module)
        ewf-tools \
        libewf-dev \
        libfuse2 \
        # VM disk image access via NBD (FAST module)
        qemu-utils \
        # File recovery and carving (FAST module)
        # bulk_extractor is not in apt — built from source in post-create.sh
        testdisk \
        foremost \
        scalpel \
        binwalk \
        # Build dependencies for suricata + bulk_extractor source builds (post-create.sh)
        libpcre2-dev \
        libyaml-dev \
        libjansson-dev \
        libmagic-dev \
        libnet1-dev \
        libpcap-dev \
        liblz4-dev \
        libcap-ng-dev \
        libcbor-dev \
        libhiredis-dev \
        libevent-dev \
        libexpat1-dev \
        libboost-dev \
        libre2-dev \
        autoconf \
        automake \
        libtool \
        flex \
        rustc \
        cargo \
        # Disk partitioning tools (FAST module)
        parted \
        kmod \
        # Network / OSINT tools (FAN module)
        whois \
        # Document conversion
        pandoc \
        # WeasyPrint PDF rendering — runtime libraries
        libcairo2 \
        libcairo2-dev \
        libffi-dev \
        libfontconfig1 \
        libgdk-pixbuf2.0-dev \
        libglib2.0-0 \
        libharfbuzz-dev \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libssl-dev \
        libxml2 \
        libxml2-dev \
        libxslt1.1 \
        libxslt1-dev \
        shared-mime-info \
        # Fonts for PDF rendering
        fonts-dejavu \
        fonts-dejavu-core \
        fonts-dejavu-extra \
        fonts-lato \
        fonts-liberation \
        fonts-liberation2 \
        fonts-noto-core \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && ln -sf /usr/bin/pip3 /usr/local/bin/pip

# ---------------------------------------------------------------------------
# SANS SIFT Workstation via cast (https://www.sans.org/tools/sift-workstation,
# Option 2a). Best-effort: `cast install` runs SaltStack states designed for a
# full Ubuntu host, so some states (e.g. systemd service management) are
# expected to fail inside a container build. Failures here don't abort the
# build — the apt-based toolset above and `post-create.sh` (idempotent
# `command -v` checks) cover the gaps. After a successful build, review the
# `cast install` log for failed states and add any missing tools above.
# ---------------------------------------------------------------------------
ARG CAST_VERSION=1.0.20
ARG TARGETARCH=arm64
RUN curl -fsSL -o /tmp/cast.deb \
        "https://github.com/ekristen/cast/releases/download/v${CAST_VERSION}/cast-v${CAST_VERSION}-linux-${TARGETARCH}.deb" \
    && dpkg -i /tmp/cast.deb \
    && rm -f /tmp/cast.deb

RUN cast install --no-os-check --user vscode teamdfir/sift \
    || echo "[sift] cast install reported failures on arm64 — see comment above for follow-up"
