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

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run entrypoint or default command later in compose
