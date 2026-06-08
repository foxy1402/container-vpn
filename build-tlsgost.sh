#!/bin/bash
# Self-healing build script for TLSGost TLS proxy

set -euo pipefail

LOG_FILE="build-tlsgost.log"
MAX_RETRIES=3
RETRY_DELAY=5

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOG_FILE"
}

error() {
    log "ERROR: $*"
    exit 1
}

check_dependencies() {
    local missing=()

    if ! command -v docker >/dev/null 2>&1; then
        missing+=("docker")
    fi

    if [ "${#missing[@]}" -gt 0 ]; then
        error "Missing dependencies: ${missing[*]}"
    fi
}

build_with_retry() {
    local attempt=1

    while [ $attempt -le $MAX_RETRIES ]; do
        log "Build attempt $attempt of $MAX_RETRIES"

        if docker build -f Dockerfile.tlsgost -t tlsgost-proxy:latest . 2>&1 | tee -a "$LOG_FILE"; then
            log "Build successful on attempt $attempt"
            return 0
        fi

        log "Build failed on attempt $attempt"

        if [ $attempt -lt $MAX_RETRIES ]; then
            log "Retrying in ${RETRY_DELAY}s..."
            sleep $RETRY_DELAY
        fi

        attempt=$((attempt + 1))
    done

    error "Build failed after $MAX_RETRIES attempts"
}

verify_image() {
    log "Verifying image..."

    if ! docker images tlsgost-proxy:latest --format "{{.Repository}}:{{.Tag}}" | grep -q "tlsgost-proxy:latest"; then
        error "Image not found after build"
    fi

    local size=$(docker images tlsgost-proxy:latest --format "{{.Size}}")
    log "Image size: $size"

    if ! docker run --rm tlsgost-proxy:latest ls -lh /app/tlsgost-proxy 2>&1 | tee -a "$LOG_FILE"; then
        error "Binary not found in image"
    fi

    log "Image verification passed"
}

main() {
    log "Starting TLSGost proxy build process"

    check_dependencies
    build_with_retry
    verify_image

    log "Build completed successfully"
    log "Run with: docker run -d -p 8443:8443 -e TLSGOST_USER=user -e TLSGOST_PASS=pass tlsgost-proxy:latest"
}

main "$@"
