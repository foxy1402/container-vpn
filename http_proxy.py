#!/usr/bin/env python3
"""
Threaded HTTP/HTTPS proxy with env-based auth and self-healing startup.
"""
import base64
import errno
import ipaddress
import logging
import os
import select
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

PID_FILE = "/tmp/http_proxy.pid"


def get_env_int(name, default, min_value, max_value):
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is invalid, using default %d", name, raw, default)
        return default
    if value < min_value or value > max_value:
        logger.warning(
            "%s=%d out of range [%d, %d], using default %d",
            name,
            value,
            min_value,
            max_value,
            default,
        )
        return default
    return value


PROXY_HOST = os.getenv("HTTP_PROXY_HOST", "0.0.0.0")
PROXY_PORT = get_env_int("HTTP_PROXY_PORT", 8080, 1, 65535)
PROXY_USER = os.getenv("HTTP_PROXY_USER", "")
PROXY_PASS = os.getenv("HTTP_PROXY_PASS", "")
MAX_CONNECTIONS = get_env_int("HTTP_MAX_CONN", 200, 1, 10000)
REQUEST_TIMEOUT = get_env_int("HTTP_PROXY_TIMEOUT", 30, 5, 300)
IDLE_TIMEOUT = get_env_int("HTTP_PROXY_IDLE_TIMEOUT", 300, 5, 86400)
AUTH_FAILURE_LIMIT = get_env_int("HTTP_AUTH_FAIL_LIMIT", 5, 1, 100)
AUTH_FAILURE_WINDOW = get_env_int("HTTP_AUTH_FAIL_WINDOW", 60, 1, 3600)
FORCE_IPV4 = os.getenv("HTTP_PROXY_FORCE_IPV4", "true").strip().lower() in ("1", "true", "yes", "on")


class ConnectionLimiter:
    def __init__(self, limit):
        self.semaphore = threading.Semaphore(limit)


LIMITER = ConnectionLimiter(MAX_CONNECTIONS)
AUTH_FAILURES = defaultdict(list)
AUTH_LOCK = threading.Lock()
ACTIVE_CONNECTIONS = 0
ACTIVE_CONNECTIONS_LOCK = threading.Lock()


class ProxyHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.client_address[0], fmt % args)

    def setup(self):
        super().setup()
        self.connection.settimeout(IDLE_TIMEOUT)

    def handle(self):
        global ACTIVE_CONNECTIONS
        if not LIMITER.semaphore.acquire(blocking=False):
            self.close_connection = True
            return
        with ACTIVE_CONNECTIONS_LOCK:
            ACTIVE_CONNECTIONS += 1
        try:
            super().handle()
        finally:
            with ACTIVE_CONNECTIONS_LOCK:
                ACTIVE_CONNECTIONS -= 1
            LIMITER.semaphore.release()

    def _is_rate_limited(self, ip):
        now = time.time()
        with AUTH_LOCK:
            windowed = [ts for ts in AUTH_FAILURES[ip] if now - ts <= AUTH_FAILURE_WINDOW]
            AUTH_FAILURES[ip] = windowed
            limited = len(windowed) >= AUTH_FAILURE_LIMIT
            if limited:
                logger.warning("Rate limit exceeded for %s", ip)
            return limited

    def _record_auth_failure(self, ip):
        with AUTH_LOCK:
            AUTH_FAILURES[ip].append(time.time())

    def _require_auth(self):
        self.send_response(407, "Proxy Authentication Required")
        self.send_header("Proxy-Authenticate", 'Basic realm="Proxy"')
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _check_auth(self):
        client_ip = self.client_address[0]
        if self._is_rate_limited(client_ip):
            self.send_error(429, "Too Many Authentication Failures")
            return False

        auth_header = self.headers.get("Proxy-Authorization", "")
        if not auth_header:
            self._require_auth()
            return False

        try:
            scheme, encoded = auth_header.split(" ", 1)
            if scheme.lower() != "basic":
                self._require_auth()
                return False
            decoded = base64.b64decode(encoded).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            self._record_auth_failure(client_ip)
            self._require_auth()
            return False

        if username != PROXY_USER or password != PROXY_PASS:
            self._record_auth_failure(client_ip)
            self._require_auth()
            return False
        return True

    def _is_safe_target(self, host):
        if not host:
            return False

        host = host.strip().strip("[]").lower()
        if host in ("localhost", "127.0.0.1", "::1"):
            return False

        try:
            ip = ipaddress.ip_address(host)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                ip = ipaddress.ip_address(addr)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return False
        except Exception:
            return False

        return True

    def _build_upstream_request(self, method):
        target_url = self.path
        parsed = urllib.parse.urlsplit(target_url)
        if not parsed.scheme or not parsed.netloc:
            host = self.headers.get("Host", "")
            if not host:
                raise ValueError("Host header is required")
            target_url = f"http://{host}{self.path}"
            parsed = urllib.parse.urlsplit(target_url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported URL scheme")

        if not self._is_safe_target(parsed.hostname):
            raise PermissionError("Target not allowed")

        body = None
        if method in ("POST", "PUT", "PATCH"):
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length) if content_length > 0 else None

        req = urllib.request.Request(target_url, data=body, method=method)
        skip_headers = {
            "proxy-authorization",
            "proxy-connection",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "host",
        }
        for key, value in self.headers.items():
            if key.lower() not in skip_headers:
                req.add_header(key, value)

        req.add_header("Connection", "close")
        return req

    def _proxy_http(self, method):
        if not self._check_auth():
            return
        try:
            req = self._build_upstream_request(method)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
                payload = response.read()
                self.send_response(response.status)

                skip_headers = {
                    "connection",
                    "proxy-connection",
                    "transfer-encoding",
                    "keep-alive",
                    "upgrade",
                }
                for key, value in response.headers.items():
                    if key.lower() not in skip_headers:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(payload)
        except PermissionError as exc:
            self.send_error(403, str(exc))
        except ValueError as exc:
            self.send_error(400, str(exc))
        except Exception as exc:
            logger.error("%s %s failed: %s", method, self.path, exc)
            self.send_error(502, f"Bad Gateway: {exc}")

    def _relay_bidirectional(self, client, upstream):
        sockets = [client, upstream]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, IDLE_TIMEOUT)
                if exceptional or not readable:
                    break
                for source in readable:
                    destination = upstream if source is client else client
                    try:
                        data = source.recv(32768)
                        if not data:
                            return
                        destination.sendall(data)
                    except (BrokenPipeError, ConnectionResetError):
                        return
        except Exception as exc:
            logger.debug("Relay error: %s", exc)

    def _connect_upstream(self, host, port):
        if FORCE_IPV4:
            addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            last_exc = None
            for family, socktype, proto, _, sockaddr in addrinfo:
                upstream = None
                try:
                    upstream = socket.socket(family, socktype, proto)
                    upstream.settimeout(REQUEST_TIMEOUT)
                    upstream.connect(sockaddr)
                    return upstream
                except OSError as exc:
                    last_exc = exc
                    if upstream:
                        upstream.close()
            if last_exc:
                raise last_exc
            raise OSError("No IPv4 address found for destination")
        return socket.create_connection((host, port), timeout=REQUEST_TIMEOUT)

    def do_CONNECT(self):
        if not self._check_auth():
            return

        self.connection.settimeout(10)

        upstream = None
        try:
            target = self.path.strip()
            if target.startswith("[") and "]:" in target:
                host, port_text = target[1:].rsplit("]:", 1)
            else:
                host, port_text = target.rsplit(":", 1)
            port = int(port_text)
            blocked_ports = {22, 23, 25, 3306, 5432, 6379, 27017}
            if port in blocked_ports:
                self.send_error(403, "Port not allowed")
                return
            if port < 1 or port > 65535:
                self.send_error(400, "Invalid port")
                return
            if not self._is_safe_target(host):
                self.send_error(403, "Target not allowed")
                return

            upstream = self._connect_upstream(host, port)
            upstream.settimeout(IDLE_TIMEOUT)

            self.send_response(200, "Connection Established")
            self.send_header("Connection", "close")
            self.end_headers()

            self.connection.settimeout(IDLE_TIMEOUT)
            self._relay_bidirectional(self.connection, upstream)
        except socket.gaierror as exc:
            logger.error("CONNECT %s failed: DNS resolution error: %s", self.path, exc)
            self.send_error(502, f"Bad Gateway: DNS resolution failed ({exc})")
        except OSError as exc:
            if exc.errno == 101:
                logger.error("CONNECT %s failed: network unreachable (likely IPv6/no route): %s", self.path, exc)
                self.send_error(502, f"Bad Gateway: network unreachable ({exc})")
            else:
                logger.error("CONNECT %s failed: %s", self.path, exc)
                self.send_error(502, f"Bad Gateway: {exc}")
        except Exception as exc:
            logger.error("CONNECT %s failed: %s", self.path, exc)
            self.send_error(502, f"Bad Gateway: {exc}")
        finally:
            if upstream:
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    upstream.close()
                except OSError:
                    pass

    def do_GET(self):
        self._proxy_http("GET")

    def do_POST(self):
        self._proxy_http("POST")

    def do_PUT(self):
        self._proxy_http("PUT")

    def do_DELETE(self):
        self._proxy_http("DELETE")

    def do_PATCH(self):
        self._proxy_http("PATCH")

    def do_HEAD(self):
        self._proxy_http("HEAD")

    def do_OPTIONS(self):
        self._proxy_http("OPTIONS")


class ProxyApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.running = True
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info("Received signal %s, initiating graceful shutdown", signum)
        self.running = False
        if self.server:
            self.server.shutdown()
        grace_period = 30
        for _ in range(grace_period):
            with ACTIVE_CONNECTIONS_LOCK:
                if ACTIVE_CONNECTIONS == 0:
                    break
            time.sleep(1)
        with ACTIVE_CONNECTIONS_LOCK:
            if ACTIVE_CONNECTIONS > 0:
                logger.warning("Force closing %d active connections", ACTIVE_CONNECTIONS)
        if self.server:
            self.server.server_close()

    def _cleanup_stale_pid_file(self):
        if not os.path.exists(PID_FILE):
            return
        try:
            with open(PID_FILE, "r", encoding="utf-8") as handle:
                pid = int(handle.read().strip())
            if pid != os.getpid():
                try:
                    os.kill(pid, 0)
                    logger.warning("Another http proxy process (pid %d) appears active", pid)
                except OSError:
                    os.remove(PID_FILE)
        except Exception:
            try:
                os.remove(PID_FILE)
            except OSError:
                pass

    def _write_pid_file(self):
        with open(PID_FILE, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))

    def _remove_pid_file(self):
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except OSError:
            pass

    def _bind_with_retries(self, attempts=30, delay=2):
        last_error = None
        for attempt in range(1, attempts + 1):
            try:
                return ProxyHTTPServer((self.host, self.port), ProxyHandler)
            except OSError as exc:
                last_error = exc
                if exc.errno in (errno.EADDRINUSE, 98, 10048):
                    logger.warning(
                        "Port %s busy (%d/%d), retrying in %ss",
                        self.port,
                        attempt,
                        attempts,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise
        raise RuntimeError(f"Cannot bind {self.host}:{self.port}: {last_error}")

    def run(self):
        self._cleanup_stale_pid_file()
        self._write_pid_file()
        logger.info("HTTP proxy starting on %s:%s", self.host, self.port)
        logger.info("Max connections: %d", MAX_CONNECTIONS)

        while self.running:
            try:
                self.server = self._bind_with_retries()
                logger.info("HTTP proxy listening on %s:%s", self.host, self.port)
                self.server.serve_forever(poll_interval=1)
            except Exception as exc:
                if not self.running:
                    break
                logger.error("HTTP server loop error: %s", exc)
                time.sleep(2)
            finally:
                if self.server:
                    try:
                        self.server.server_close()
                    except OSError:
                        pass
                    self.server = None
        self._remove_pid_file()


def main():
    if not PROXY_USER or not PROXY_PASS:
        logger.error("HTTP_PROXY_USER and HTTP_PROXY_PASS must be set via environment")
        sys.exit(1)

    app = ProxyApp(PROXY_HOST, PROXY_PORT)
    app.run()


if __name__ == "__main__":
    main()
