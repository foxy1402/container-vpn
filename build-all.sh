#!/bin/bash

#######################################################################
# Multi-Service Docker Image Builder
# Builds separate images for: SOCKS5, HTTP Proxy, WireGuard
# Each image can be deployed independently on cloud platforms
#######################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
REGISTRY="${REGISTRY:-ghcr.io}"
NAMESPACE="${NAMESPACE:-yourusername}"
VERSION="${VERSION:-latest}"

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       Cloud-Ready Proxy Images Builder                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to build image
build_image() {
    local service=$1
    local dockerfile=$2
    local tag=$3
    
    echo -e "${YELLOW}Building ${service}...${NC}"
    
    local image_name="${REGISTRY}/${NAMESPACE}/proxy:${tag}"
    
    docker build \
        -f "${dockerfile}" \
        -t "proxy:${tag}" \
        -t "${image_name}" \
        . || {
        echo -e "${RED}✗ Failed to build ${service}${NC}"
        return 1
    }
    
    echo -e "${GREEN}✓ Built: proxy:${tag}${NC}"
    echo -e "${GREEN}✓ Tagged: ${image_name}${NC}"
    echo ""
}

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker not found${NC}"
    exit 1
fi

echo -e "${CYAN}Registry: ${REGISTRY}${NC}"
echo -e "${CYAN}Namespace: ${NAMESPACE}${NC}"
echo -e "${CYAN}Version: ${VERSION}${NC}"
echo ""

# Build all images
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Building Images...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

build_image "SOCKS5 Proxy" "Dockerfile" "socks5"
build_image "HTTP Proxy" "Dockerfile.http" "http-proxy"
build_image "WireGuard VPN" "Dockerfile.wireguard" "wireguard"

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Local Images:${NC}"
docker images | grep "proxy" | grep -E "socks5|http-proxy|wireguard"
echo ""
echo -e "${CYAN}Available Tags:${NC}"
echo "  • proxy:socks5"
echo "  • proxy:http-proxy"
echo "  • proxy:wireguard"
echo ""
echo -e "${CYAN}Registry Images (for pushing):${NC}"
echo "  • ${REGISTRY}/${NAMESPACE}/proxy:socks5"
echo "  • ${REGISTRY}/${NAMESPACE}/proxy:http-proxy"
echo "  • ${REGISTRY}/${NAMESPACE}/proxy:wireguard"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Test locally:"
echo "   docker run -d -p 1080:1080 -e SOCKS5_USER=user -e SOCKS5_PASS=pass proxy:socks5"
echo ""
echo "2. Push to registry:"
echo "   docker push ${REGISTRY}/${NAMESPACE}/proxy:socks5"
echo "   docker push ${REGISTRY}/${NAMESPACE}/proxy:http-proxy"
echo "   docker push ${REGISTRY}/${NAMESPACE}/proxy:wireguard"
echo ""
echo "3. Deploy on Claw Cloud using these image URLs"
echo ""
