FROM debian:13-slim

# Metadata
LABEL org.opencontainers.image.title="SOCKS5 Proxy"
LABEL org.opencontainers.image.description="Production-ready SOCKS5 proxy with self-healing"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="CloudProxy"
LABEL service.type="socks5"

# Install dependencies in single layer for minimal size
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create app directory
WORKDIR /app

# Copy application
COPY socks5_proxy.py /app/socks5_proxy.py
RUN chmod +x /app/socks5_proxy.py

# Create non-root user
RUN useradd -r -u 1000 -s /bin/false appuser && \
    chown -R appuser:appuser /app && \
    mkdir -p /tmp && \
    chown appuser:appuser /tmp

# Environment variables
ENV SOCKS5_HOST=0.0.0.0 \
    SOCKS5_PORT=1080 \
    SOCKS5_USER= \
    SOCKS5_PASS= \
    SOCKS5_MAX_CONN=50 \
    SOCKS5_TIMEOUT=30 \
    SOCKS5_IDLE_TIMEOUT=300 \
    PYTHONUNBUFFERED=1

# Expose port
EXPOSE 1080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import os,socket; s=socket.socket(); s.settimeout(5); s.connect(('127.0.0.1', int(os.getenv('SOCKS5_PORT','1080')))); s.close()"

# Run as non-root
USER appuser

# Start application
CMD ["python3", "-u", "/app/socks5_proxy.py"]
