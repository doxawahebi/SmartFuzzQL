FROM python:3.10-slim

WORKDIR /app

# Install dependencies needed for pipeline (git, build-essential, curl, docker)
RUN apt-get update && \
    apt-get install -y git build-essential curl docker.io clang cmake && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run entrypoint or default command later in compose
