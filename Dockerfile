# ── Stage 1: Build projectdiscovery Go tools ──────────────────────────────────
FROM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git gcc musl-dev

# Install all projectdiscovery tools used in the Hunt3r pipeline.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest   && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest                 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest               && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest             && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest          && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest            && \
    go install github.com/projectdiscovery/uncover/cmd/uncover@latest           && \
    go install github.com/hahwul/urlfinder@latest                               && \
    go install github.com/sw33tLie/bbscope@latest

# ── Stage 2: Python worker image ──────────────────────────────────────────────
FROM python:3.11-slim

# Runtime system libraries needed by Python packages (lightgbm → libgomp1).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Go binaries into a directory already on PATH.
COPY --from=go-builder /go/bin/ /usr/local/bin/

WORKDIR /app

# Install Python dependencies (base + Celery broker extras).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "celery[redis]"

# Copy source code.
COPY . .

# Ensure recon working directories exist (bind-mounted in compose, created here
# as a fallback for standalone container runs).
RUN mkdir -p recon/baselines recon/db recon/cache logs reports data

# Default: run as Celery worker consuming the hunt3r.scan queue.
CMD ["python", "worker.py", "--concurrency=1", "--loglevel=info"]
