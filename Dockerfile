FROM python:3.12-slim

RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt/lists \
    apt-get update && apt-get install -y --no-install-recommends nmap

WORKDIR /app
COPY os_fingerprint.py .
COPY data/filter_scan.py data/filter_scan.py
COPY data/analyse_scan.py data/analyse_scan.py

ENTRYPOINT ["python3"]
