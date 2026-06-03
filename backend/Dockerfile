FROM python:3.10-slim

WORKDIR /app

# Install dependencies needed for pipeline (git, build-essential, curl, docker, wget)
RUN apt-get update && \
    apt-get install -y git build-essential curl docker.io clang cmake wget autoconf automake libtool pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Install CodeQL CLI
RUN wget -q https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \
    && tar -xzf codeql-bundle-linux64.tar.gz -C /opt \
    && rm codeql-bundle-linux64.tar.gz
ENV PATH="/opt/codeql:$PATH"

# Install Joern (build-free SAST fallback). Joern runs on the JVM and needs JDK >= 17
# (this slim image ships no JDK; the current Debian base packages openjdk-21). Pin a
# known-good release via JOERN_VERSION for reproducible builds; leave empty to take the
# latest. Layered after CodeQL so the CodeQL layer stays cached when only Joern changes.
RUN apt-get update && apt-get install -y openjdk-21-jre-headless unzip && rm -rf /var/lib/apt/lists/*
ARG JOERN_VERSION=v4.0.380
RUN curl -fsSL https://github.com/joernio/joern/releases/latest/download/joern-install.sh -o /tmp/joern-install.sh \
    && chmod +x /tmp/joern-install.sh \
    && /tmp/joern-install.sh --install-dir=/opt/joern --without-plugins ${JOERN_VERSION:+--version=$JOERN_VERSION} \
    && rm /tmp/joern-install.sh
ENV PATH="/opt/joern/joern-cli:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run entrypoint or default command later in compose
