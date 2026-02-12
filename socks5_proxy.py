#!/usr/bin/env python3
"""
SOCKS5 proxy with env-based auth and container-friendly self-healing.
"""
import errno
import logging
import os
import select
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from threading import Lock, Semaphore


logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

PID_FILE = "/tmp/socks5_proxy.pid"


def get_env_int(name, default, min_value, max_value):
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is invalid, using default %d", name, raw, default)
        return default
    if value < min_value or value > max_value:
        logger.warning(
            "%s=%d is out of range [%d, %d], using default %d",
            name,
            value,
            min_value,
            max_value,
            default,
        )
        return default
    return value


PROXY_HOST = os.getenv("SOCKS5_HOST", "0.0.0.0")
PROXY_PORT = get_env_int("SOCKS5_PORT", 1080, 1, 65535)
PROXY_USER = os.getenv("SOCKS5_USER", "")
PROXY_PASS = os.getenv("SOCKS5_PASS", "")
MAX_CONNECTIONS = get_env_int("SOCKS5_MAX_CONN", 200, 1, 10000)
CONNECTION_TIMEOUT = get_env_int("SOCKS5_TIMEOUT", 15, 3, 300)
IDLE_TIMEOUT = get_env_int("SOCKS5_IDLE_TIMEOUT", 300, 5, 86400)
AUTH_FAILURE_LIMIT = get_env_int("SOCKS5_AUTH_FAIL_LIMIT", 5, 1, 100)
AUTH_FAILURE_WINDOW = get_env_int("SOCKS5_AUTH_FAIL_WINDOW", 60, 1, 3600)


class SOCKS5Server:
    def __init__(self, host, port, username, password, max_connections):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.max_connections = max_connections
        self.connection_semaphore = Semaphore(max_connections)
        self.active_connections = 0
        self.conn_lock = Lock()
        self.auth_failures = defaultdict(list)
        self.auth_lock = Lock()
        self.server = None
        self.running = False

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info("Received signal %s, initiating graceful shutdown", signum)
        self.running = False
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
        grace_period = 30
        for _ in range(grace_period):
            with self.conn_lock:
                if self.active_connections == 0:
                    break
            time.sleep(1)
        with self.conn_lock:
            if self.active_connections > 0:
                logger.warning("Force closing %d active connections", self.active_connections)
        self._cleanup_pid_file()
        sys.exit(0)

    def _write_pid_file(self):
        try:
            with open(PID_FILE, "w", encoding="utf-8") as handle:
                handle.write(str(os.getpid()))
        except OSError as exc:
            logger.warning("Cannot write pid file: %s", exc)

    def _cleanup_pid_file(self):
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except OSError as exc:
            logger.warning("Cannot remove pid file: %s", exc)

    def _cleanup_stale_pid_file(self):
        if not os.path.exists(PID_FILE):
            return
        try:
            with open(PID_FILE, "r", encoding="utf-8") as handle:
                pid = int(handle.read().strip())
            if pid == os.getpid():
                return
            try:
                os.kill(pid, 0)
                logger.warning("Another socks5 process (pid %d) looks active", pid)
            except OSError:
                logger.info("Removing stale pid file")
                os.remove(PID_FILE)
        except Exception:
            try:
                os.remove(PID_FILE)
            except OSError:
                pass

    def _recv_exact(self, sock, size):
        buf = bytearray()
        while len(buf) < size:
            chunk = sock.recv(size - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _check_rate_limit(self, ip):
        now = time.time()
        with self.auth_lock:
            history = [ts for ts in self.auth_failures[ip] if now - ts <= AUTH_FAILURE_WINDOW]
            self.auth_failures[ip] = history
            allowed = len(history) < AUTH_FAILURE_LIMIT
            if not allowed:
                logger.warning("Rate limit exceeded for %s", ip)
            return allowed

    def _record_auth_failure(self, ip):
        with self.auth_lock:
            self.auth_failures[ip].append(time.time())

    def _reply(self, sock, rep):
        sock.sendall(struct.pack("!BBBBIH", 5, rep, 0, 1, 0, 0))

    def _relay(self, client, remote):
        sockets = [client, remote]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, IDLE_TIMEOUT)
                if exceptional or not readable:
                    break
                for source in readable:
                    destination = remote if source is client else client
                    try:
                        data = source.recv(32768)
                        if not data:
                            return
                        destination.sendall(data)
                    except (BrokenPipeError, ConnectionResetError):
                        return
        except Exception as exc:
            logger.debug("Relay error: %s", exc)

    def _handle_client(self, client_socket, client_address):
        client_ip = client_address[0]
        remote = None
        try:
            client_socket.settimeout(CONNECTION_TIMEOUT)

            greeting = self._recv_exact(client_socket, 2)
            if not greeting:
                return
            version, nmethods = struct.unpack("!BB", greeting)
            if version != 5:
                return

            methods = self._recv_exact(client_socket, nmethods)
            if not methods:
                return
            if 2 in methods:
                client_socket.sendall(struct.pack("!BB", 5, 2))
            else:
                client_socket.sendall(struct.pack("!BB", 5, 255))
                return

            if not self._check_rate_limit(client_ip):
                client_socket.sendall(struct.pack("!BB", 1, 1))
                return

            auth_header = self._recv_exact(client_socket, 2)
            if not auth_header:
                return
            auth_version, user_len = struct.unpack("!BB", auth_header)
            if auth_version != 1:
                client_socket.sendall(struct.pack("!BB", 1, 1))
                return

            user_raw = self._recv_exact(client_socket, user_len)
            if user_raw is None:
                return
            pass_len_raw = self._recv_exact(client_socket, 1)
            if pass_len_raw is None:
                return
            pass_len = pass_len_raw[0]
            pass_raw = self._recv_exact(client_socket, pass_len)
            if pass_raw is None:
                return

            username = user_raw.decode("utf-8", errors="ignore")
            password = pass_raw.decode("utf-8", errors="ignore")
            if username != self.username or password != self.password:
                self._record_auth_failure(client_ip)
                client_socket.sendall(struct.pack("!BB", 1, 1))
                logger.warning("Auth failed from %s", client_ip)
                return
            client_socket.sendall(struct.pack("!BB", 1, 0))

            req_header = self._recv_exact(client_socket, 4)
            if not req_header:
                return
            _, cmd, _, atyp = struct.unpack("!BBBB", req_header)
            if cmd != 1:
                self._reply(client_socket, 7)
                return

            if atyp == 1:
                addr_raw = self._recv_exact(client_socket, 4)
                if not addr_raw:
                    return
                dst = socket.inet_ntoa(addr_raw)
            elif atyp == 3:
                domain_len = self._recv_exact(client_socket, 1)
                if not domain_len:
                    return
                domain = self._recv_exact(client_socket, domain_len[0])
                if not domain:
                    return
                dst = domain.decode("utf-8", errors="ignore")
            elif atyp == 4:
                self._reply(client_socket, 8)
                return
            else:
                self._reply(client_socket, 8)
                return

            port_raw = self._recv_exact(client_socket, 2)
            if not port_raw:
                return
            dst_port = struct.unpack("!H", port_raw)[0]

            remote = socket.create_connection((dst, dst_port), timeout=CONNECTION_TIMEOUT)
            remote.settimeout(IDLE_TIMEOUT)
            bind_host, bind_port = remote.getsockname()[:2]
            if ":" in bind_host:
                bind_host = "0.0.0.0"
            client_socket.sendall(
                struct.pack("!BBBBIH", 5, 0, 0, 1, struct.unpack("!I", socket.inet_aton(bind_host))[0], bind_port)
            )
            client_socket.settimeout(IDLE_TIMEOUT)
            self._relay(client_socket, remote)
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.error("Client %s error: %s", client_ip, exc)
        finally:
            for sock in (client_socket, remote):
                if not sock:
                    continue
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass

    def _handle_client_wrapper(self, client, address):
        with self.conn_lock:
            self.active_connections += 1
        try:
            self._handle_client(client, address)
        finally:
            with self.conn_lock:
                self.active_connections -= 1
            self.connection_semaphore.release()

    def _bind_with_retries(self, attempts=30, delay=2):
        last_error = None
        for attempt in range(1, attempts + 1):
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.host, self.port))
                server.listen(min(1024, self.max_connections))
                server.settimeout(2)
                return server
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

    def start(self):
        self._cleanup_stale_pid_file()
        self._write_pid_file()
        self.running = True
        logger.info("SOCKS5 starting on %s:%s", self.host, self.port)
        logger.info("Max connections: %s", self.max_connections)

        while self.running:
            try:
                self.server = self._bind_with_retries()
                logger.info("SOCKS5 listening on %s:%s", self.host, self.port)
                while self.running:
                    try:
                        client, address = self.server.accept()
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        if self.running:
                            logger.warning("Accept loop reset: %s", exc)
                        break

                    if not self.connection_semaphore.acquire(blocking=False):
                        logger.warning("Connection limit reached, rejecting %s", address[0])
                        client.close()
                        continue

                    threading.Thread(
                        target=self._handle_client_wrapper,
                        args=(client, address),
                        daemon=True,
                    ).start()
            except Exception as exc:
                if not self.running:
                    break
                logger.error("Server loop error: %s", exc)
                time.sleep(2)
            finally:
                if self.server:
                    try:
                        self.server.close()
                    except OSError:
                        pass
                    self.server = None
        self._cleanup_pid_file()
        logger.info("SOCKS5 stopped")


def main():
    if not PROXY_USER or not PROXY_PASS:
        logger.error("SOCKS5_USER and SOCKS5_PASS must be set via environment")
        sys.exit(1)
    server = SOCKS5Server(PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASS, MAX_CONNECTIONS)
    server.start()


if __name__ == "__main__":
    main()
