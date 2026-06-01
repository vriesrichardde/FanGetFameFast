FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Prevent interactive wireshark/tshark package configuration during image build.
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections

RUN rm -f /etc/apt/sources.list.d/yarn.list /etc/apt/sources.list.d/yarn.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        # Build tools
        build-essential \
        cmake \
        pkg-config \
        curl \
        wget \
        git \
        # Node.js (Claude Code CLI)
        nodejs \
        npm \
        # Network forensics
        tshark \
        wireshark-common \
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
    && rm -rf /var/lib/apt/lists/*
