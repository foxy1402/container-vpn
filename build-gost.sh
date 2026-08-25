#!/bin/bash
# Self-healing build script for GOST multi-protocol proxy

set -euo pipefail

LOG_FILE="build-gost.log"
MAX_RETRIES=3
RETRY_DELAY=5
IMAGE_NAME="gost-proxy"
DOCKERFILE="Dockerfile.gost"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

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

        # --pull refreshes the pinned base images; without it a stale local
        # copy of a base tag is reused silently.
        if docker build --pull -f "$DOCKERFILE" \
            -t "${IMAGE_NAME}:${VERSION}" \
            -t "${IMAGE_NAME}:latest" \
            . 2>&1 | tee -a "$LOG_FILE"; then
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

record_base_digests() {
    # Record the actual base-image digests used, for provenance auditing.
    log "Base image digests:"
    grep -i '^FROM' "$DOCKERFILE" | awk '{print $2}' | while read -r base; do
        docker image inspect "$base" \
            --format '  {{index .RepoTags 0}} -> {{json .RepoDigests}}' 2>/dev/null \
            | tee -a "$LOG_FILE" || log "  WARNING: could not inspect $base"
    done
}

verify_image() {
    log "Verifying image..."

    if ! docker images "${IMAGE_NAME}:${VERSION}" --format "{{.Repository}}:{{.Tag}}" | grep -q "${IMAGE_NAME}:${VERSION}"; then
        error "Image not found after build"
    fi

    # Check image size
    local size
    size=$(docker images "${IMAGE_NAME}:${VERSION}" --format "{{.Size}}")
    log "Image size: $size"

    # Actually execute the binary: -version exercises the built artifact,
    # not just its presence on disk.
    local version_out
    if version_out=$(docker run --rm "${IMAGE_NAME}:${VERSION}" -version 2>&1); then
        log "Binary version check: $version_out"
    else
        error "Binary failed to run in container: $version_out"
    fi

    log "Image verification passed"
}

main() {
    log "Starting GOST proxy build process (version: $VERSION)"

    check_dependencies
    build_with_retry
    record_base_digests
    verify_image

    log "Build completed successfully"
    log "Run with: docker run -d -p 127.0.0.1:8080:8080 -e GOST_USER=<user> -e GOST_PASS=<strong-random-password> ${IMAGE_NAME}:${VERSION}"
}

main "$@"
