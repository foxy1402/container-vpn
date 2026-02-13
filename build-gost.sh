#!/bin/bash
# Self-healing build script for GOST multi-protocol proxy

set -euo pipefail

LOG_FILE="build-gost.log"
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
        
        if docker build -f Dockerfile.gost -t gost-proxy:latest . 2>&1 | tee -a "$LOG_FILE"; then
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
    
    if ! docker images gost-proxy:latest --format "{{.Repository}}:{{.Tag}}" | grep -q "gost-proxy:latest"; then
        error "Image not found after build"
    fi
    
    # Check image size
    local size=$(docker images gost-proxy:latest --format "{{.Size}}")
    log "Image size: $size"
    
    # Verify binary exists in image
    if ! docker run --rm gost-proxy:latest ls -lh /app/gost-proxy 2>&1 | tee -a "$LOG_FILE"; then
        error "Binary not found in image"
    fi
    
    log "Image verification passed"
}

main() {
    log "Starting GOST proxy build process"
    
    check_dependencies
    build_with_retry
    verify_image
    
    log "Build completed successfully"
    log "Run with: docker run -d -p 8080:8080 -e GOST_USER=user -e GOST_PASS=pass gost-proxy:latest"
}

main "$@"
