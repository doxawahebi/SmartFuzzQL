FROM aflplusplus/aflplusplus:latest

# Install prerequisites for CodeQL and Python scripts
# - openjdk-11-jdk: CodeQL requires Java to run
# - python3, python3-pip: Required for the orchestration script
# - wget, unzip: Required to download and extract CodeQL
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openjdk-11-jdk \
    python3 \
    python3-pip \
    wget \
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
