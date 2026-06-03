FROM aflplusplus/aflplusplus:latest

# Install prerequisites for CodeQL and Python scripts
# - openjdk-11-jdk: CodeQL requires Java to run
# - python3, python3-pip: Required for the orchestration script
# - wget, unzip: Required to download and extract CodeQL
# openjdk-17: CodeQL's bundle is self-contained, but Joern (build-free SAST fallback)
#   runs on the JVM and needs JDK >= 17.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    wget \
    curl \
    unzip \
    gcc \
    clang \
    make \
    libpcap-dev \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

# Download and install CodeQL CLI bundle
RUN wget https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz -O /tmp/codeql.tar.gz && \
    tar -xvzf /tmp/codeql.tar.gz -C /opt && \
    rm /tmp/codeql.tar.gz

# Add CodeQL to path
ENV PATH="/opt/codeql:${PATH}"

# Install Joern (build-free SAST fallback used when the target won't build). Pin a
# known-good release via JOERN_VERSION for reproducibility; leave empty for latest.
ARG JOERN_VERSION=v4.0.380
RUN curl -fsSL https://github.com/joernio/joern/releases/latest/download/joern-install.sh -o /tmp/joern-install.sh \
    && chmod +x /tmp/joern-install.sh \
    && /tmp/joern-install.sh --install-dir=/opt/joern --without-plugins ${JOERN_VERSION:+--version=$JOERN_VERSION} \
    && rm /tmp/joern-install.sh
ENV PATH="/opt/joern/joern-cli:${PATH}"
