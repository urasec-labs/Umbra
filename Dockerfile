FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends nmap git fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd -r -u 10001 umbra && mkdir -p /app/data && chown -R umbra /app/data
USER umbra
VOLUME ["/app/data"]

# Example: docker run --rm -v umbra-data:/app/data -e UMBRA_DISCORD_WEBHOOK=... umbra monitor -d example.com --interval 3600
ENTRYPOINT ["python", "umbra.py"]
CMD ["--help"]
