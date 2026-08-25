#!/bin/sh
# Health check for GOST multi-protocol proxy.
# Delegates to the binary's -healthcheck mode, which probes the listener end
# to end (connect -> HTTP CONNECT with auth -> expects the egress policy to
# reject the loopback target with 403). A wedged accept loop or broken auth
# path therefore reports unhealthy, unlike a bare LISTEN check.
exec /app/gost-proxy -healthcheck
