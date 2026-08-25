#!/bin/sh
# Health check for TLSGost TLS proxy.
# Delegates to the binary's -healthcheck mode, which performs a full TLS
# handshake against the live listener, authenticates, and expects the egress
# policy to reject a loopback CONNECT with 403. A wedged TLS stack or broken
# auth path therefore reports unhealthy, unlike a bare LISTEN check.
exec /app/tlsgost-proxy -healthcheck
