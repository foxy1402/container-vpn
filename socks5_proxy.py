#!/usr/bin/env python3
"""
SOCKS5 Proxy Server for Debian 13 Container Environment
Production-ready with security hardening and self-healing
Run on port 1080 with username/password authentication

Environment Variables:
    SOCKS5_HOST: Bind address (default: 0.0.0.0)
    SOCKS5_PORT: Port number (default: 1080)
    SOCKS5_USER: Username (default: proxyuser)
    SOCKS5_PASS: Password (default: proxypass)
    SOCKS5_MAX_CONN: Maximum connections (default: 50)
    SOCKS5_TIMEOUT: Connection timeout in seconds (default: 30)
    SOCKS5_IDLE_TIMEOUT: Idle timeout in seconds (default: 300)
"""
import socket
import threading
import struct
import logging
import time
import os
import sys
import signal
import subprocess
from collections import defaultdict
from threading import Semaphore, Lock

# Try to import psutil, but make it optional
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Configuration (can be overridden with environment variables)
PROXY_HOST = os.getenv('SOCKS5_HOST', '0.0.0.0')
PROXY_PORT = int(os.getenv('SOCKS5_PORT', '1080'))
PROXY_USER = os.getenv('SOCKS5_USER', 'proxyuser')
PROXY_PASS = os.getenv('SOCKS5_PASS', 'proxypass')
MAX_CONNECTIONS = int(os.getenv('SOCKS5_MAX_CONN', '50'))
CONNECTION_TIMEOUT = int(os.getenv('SOCKS5_TIMEOUT', '30'))
IDLE_TIMEOUT = int(os.getenv('SOCKS5_IDLE_TIMEOUT', '300'))

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# PID file for instance tracking
PID_FILE = '/tmp/socks5_proxy.pid'

class SOCKS5Server:
    def __init__(self, host, port, username, password, max_connections=50):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.server = None
        self.max_connections = max_connections
        self.connection_semaphore = Semaphore(max_connections)
        self.active_connections = 0
        self.conn_lock = Lock()
        self.running = False
        
        # Rate limiting for auth failures (IP -> [timestamps])
        self.auth_failures = defaultdict(list)
        self.auth_lock = Lock()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        self._cleanup_pid_file()
        sys.exit(0)

    def _write_pid_file(self):
        """Write current process ID to file"""
        try:
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
            logger.debug(f"PID {os.getpid()} written to {PID_FILE}")
        except Exception as e:
            logger.warning(f"Failed to write PID file: {e}")
    
    def _cleanup_pid_file(self):
        """Remove PID file on shutdown"""
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
                logger.debug("PID file removed")
        except Exception as e:
            logger.warning(f"Failed to remove PID file: {e}")
    
    def _check_and_kill_old_instances(self):
        """Check for old instances and kill them if needed"""
        if not os.path.exists(PID_FILE):
            return
        
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())
            
            # Check if process exists
            if HAS_PSUTIL:
                # Use psutil for better process handling
                if psutil.pid_exists(old_pid):
                    try:
                        old_process = psutil.Process(old_pid)
                        # Verify it's actually our script
                        if 'socks5_proxy.py' in ' '.join(old_process.cmdline()):
                            logger.warning(f"Found old instance (PID {old_pid}), terminating...")
                            old_process.terminate()
                            time.sleep(2)
                            
                            # Force kill if still alive
                            if old_process.is_running():
                                logger.warning(f"Force killing old instance (PID {old_pid})")
                                old_process.kill()
                                time.sleep(1)
                            
                            logger.info("Old instance terminated successfully")
                    except psutil.NoSuchProcess:
                        pass
            else:
                # Fallback without psutil - use kill command
                try:
                    # Check if process exists
                    os.kill(old_pid, 0)  # Signal 0 just checks existence
                    # Process exists, kill it
                    logger.warning(f"Found old instance (PID {old_pid}), terminating...")
                    os.kill(old_pid, signal.SIGTERM)
                    time.sleep(2)
                    
                    # Check if still alive and force kill
                    try:
                        os.kill(old_pid, 0)
                        logger.warning(f"Force killing old instance (PID {old_pid})")
                        os.kill(old_pid, signal.SIGKILL)
                        time.sleep(1)
                    except OSError:
                        pass  # Process is dead
                    
                    logger.info("Old instance terminated successfully")
                except OSError:
                    # Process doesn't exist, just clean up PID file
                    pass
            
            # Clean up stale PID file
            os.remove(PID_FILE)
        except Exception as e:
            logger.debug(f"Error checking old instances: {e}")
    
    def _check_port_availability(self):
        """Check if port is available and try to free it"""
        try:
            # Try to bind to check availability
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind((self.host, self.port))
            test_socket.close()
            logger.info(f"Port {self.port} is available")
            return True
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logger.warning(f"Port {self.port} is in use, attempting to free it...")
                
                if HAS_PSUTIL:
                    # Use psutil to find and kill processes using the port
                    for proc in psutil.process_iter(['pid', 'name', 'connections']):
                        try:
                            for conn in proc.info['connections'] or []:
                                if conn.laddr.port == self.port and conn.status == 'LISTEN':
                                    logger.warning(f"Killing process {proc.pid} ({proc.name()}) using port {self.port}")
                                    proc.terminate()
                                    time.sleep(1)
                                    if proc.is_running():
                                        proc.kill()
                                    time.sleep(1)
                                    return True
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                else:
                    # Fallback: use lsof or netstat
                    try:
                        # Try lsof first
                        result = subprocess.run(
                            ['lsof', '-ti', f':{self.port}'],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            pid = int(result.stdout.strip().split()[0])
                            logger.warning(f"Killing process {pid} using port {self.port}")
                            os.kill(pid, signal.SIGTERM)
                            time.sleep(1)
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except OSError:
                                pass
                            time.sleep(1)
                            return True
                    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
                        # lsof not available or failed, try fuser
                        try:
                            result = subprocess.run(
                                ['fuser', '-k', f'{self.port}/tcp'],
                                capture_output=True,
                                timeout=5
                            )
                            time.sleep(1)
                            logger.info(f"Attempted to free port {self.port} with fuser")
                            return True
                        except (FileNotFoundError, subprocess.TimeoutExpired):
                            logger.warning("Cannot free port - lsof/fuser not available")
                
                logger.error(f"Failed to free port {self.port}")
                return False
            else:
                logger.error(f"Port check failed: {e}")
                return False
    
    def check_rate_limit(self, ip):
        """Check if IP is rate limited (max 5 failures per 60 seconds)"""
        with self.auth_lock:
            now = time.time()
            # Clean old entries
            self.auth_failures[ip] = [t for t in self.auth_failures[ip] if now - t < 60]
            
            if len(self.auth_failures[ip]) >= 5:
                return False
            return True
    
    def record_auth_failure(self, ip):
        """Record authentication failure for rate limiting"""
        with self.auth_lock:
            self.auth_failures[ip].append(time.time())

    def handle_client(self, client_socket, address):
        client_ip = address[0]
        try:
            # Set socket timeout to prevent hanging
            client_socket.settimeout(CONNECTION_TIMEOUT)
            
            # SOCKS5 greeting
            greeting = client_socket.recv(2)
            if len(greeting) != 2:
                logger.warning(f"Invalid greeting from {address}")
                return
            
            version, nmethods = struct.unpack("!BB", greeting)
            if version != 5:
                logger.warning(f"Unsupported SOCKS version {version} from {address}")
                return
            
            methods = client_socket.recv(nmethods)
            if len(methods) != nmethods:
                logger.warning(f"Invalid methods from {address}")
                return
            
            # Check for username/password auth (method 2)
            if 2 not in methods:
                client_socket.sendall(struct.pack("!BB", 5, 255))  # No acceptable methods
                return
            
            # Request username/password auth
            client_socket.sendall(struct.pack("!BB", 5, 2))
            
            # Check rate limit before processing auth
            if not self.check_rate_limit(client_ip):
                logger.warning(f"Rate limit exceeded from {client_ip}")
                client_socket.sendall(struct.pack("!BB", 1, 1))
                return
            
            # Receive auth credentials
            auth_version = client_socket.recv(1)
            if len(auth_version) != 1:
                return
            
            username_len_data = client_socket.recv(1)
            if len(username_len_data) != 1:
                return
            username_len = struct.unpack("!B", username_len_data)[0]
            
            username_data = client_socket.recv(username_len)
            if len(username_data) != username_len:
                return
            username = username_data.decode('utf-8', errors='ignore')
            
            password_len_data = client_socket.recv(1)
            if len(password_len_data) != 1:
                return
            password_len = struct.unpack("!B", password_len_data)[0]
            
            password_data = client_socket.recv(password_len)
            if len(password_data) != password_len:
                return
            password = password_data.decode('utf-8', errors='ignore')
            
            # Verify credentials
            if username != self.username or password != self.password:
                self.record_auth_failure(client_ip)
                client_socket.sendall(struct.pack("!BB", 1, 1))  # Auth failed
                logger.warning(f"Auth failed from {client_ip} - user: {username}")
                return
            
            # Auth success
            client_socket.sendall(struct.pack("!BB", 1, 0))
            logger.info(f"Auth successful from {client_ip} - user: {username}")
            
            # SOCKS5 request
            request_header = client_socket.recv(4)
            if len(request_header) != 4:
                return
            
            version, cmd, _, address_type = struct.unpack("!BBBB", request_header)
            
            # Only support CONNECT command (cmd=1)
            if cmd != 1:
                logger.warning(f"Unsupported command {cmd} from {address}")
                reply = struct.pack("!BBBBIH", 5, 7, 0, 1, 0, 0)  # Command not supported
                client_socket.sendall(reply)
                return
            
            if address_type == 1:  # IPv4
                addr_data = client_socket.recv(4)
                if len(addr_data) != 4:
                    return
                address = socket.inet_ntoa(addr_data)
            elif address_type == 3:  # Domain name
                domain_length_data = client_socket.recv(1)
                if len(domain_length_data) != 1:
                    return
                domain_length = domain_length_data[0]
                domain_data = client_socket.recv(domain_length)
                if len(domain_data) != domain_length:
                    return
                address = domain_data.decode('utf-8', errors='ignore')
            elif address_type == 4:  # IPv6
                logger.warning(f"IPv6 not supported from {client_ip}")
                reply = struct.pack("!BBBBIH", 5, 8, 0, 1, 0, 0)  # Address type not supported
                client_socket.sendall(reply)
                return
            else:
                logger.warning(f"Unknown address type {address_type} from {client_ip}")
                return
            
            port_data = client_socket.recv(2)
            if len(port_data) != 2:
                return
            port = struct.unpack('!H', port_data)[0]
            
            # Connect to target
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(CONNECTION_TIMEOUT)
                remote.connect((address, port))
                remote.settimeout(IDLE_TIMEOUT)  # Set idle timeout after connection
                bind_address = remote.getsockname()
                logger.info(f"{client_ip} -> {address}:{port} connected")
            except socket.timeout:
                logger.error(f"Connection timeout to {address}:{port}")
                reply = struct.pack("!BBBBIH", 5, 4, 0, 1, 0, 0)  # Host unreachable
                client_socket.sendall(reply)
                return
            except socket.gaierror as e:
                logger.error(f"DNS resolution failed for {address}: {e}")
                reply = struct.pack("!BBBBIH", 5, 4, 0, 1, 0, 0)  # Host unreachable
                client_socket.sendall(reply)
                return
            except (ConnectionRefusedError, OSError) as e:
                logger.error(f"Connection refused to {address}:{port} - {e}")
                reply = struct.pack("!BBBBIH", 5, 5, 0, 1, 0, 0)  # Connection refused
                client_socket.sendall(reply)
                return
            except Exception as e:
                logger.error(f"Connection failed to {address}:{port} - {e}")
                reply = struct.pack("!BBBBIH", 5, 1, 0, 1, 0, 0)  # General failure
                client_socket.sendall(reply)
                return
            
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", 5, 0, 0, 1, addr, port)
            client_socket.sendall(reply)
            
            # Set idle timeout for client socket
            client_socket.settimeout(IDLE_TIMEOUT)
            
            # Relay data
            self.relay(client_socket, remote)
            
        except socket.timeout:
            logger.warning(f"Timeout from {client_ip}")
        except ConnectionResetError:
            logger.info(f"Connection reset by {client_ip}")
        except BrokenPipeError:
            logger.info(f"Broken pipe from {client_ip}")
        except Exception as e:
            logger.error(f"Error handling client {client_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def relay(self, client, remote):
        """Bidirectional data relay between client and remote"""
        sockets_closed = {'client': False, 'remote': False}
        close_lock = Lock()
        
        def safe_close(sock, name):
            """Safely close socket only once"""
            with close_lock:
                if not sockets_closed[name]:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sockets_closed[name] = True
        
        def forward(source, destination, src_name, dst_name):
            try:
                while True:
                    data = source.recv(8192)
                    if not data:
                        break
                    destination.sendall(data)
            except socket.timeout:
                pass  # Idle timeout reached
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass  # Connection closed
            except Exception as e:
                logger.debug(f"Relay error: {e}")
            finally:
                safe_close(source, src_name)
                safe_close(destination, dst_name)

        client_to_remote = threading.Thread(
            target=forward, 
            args=(client, remote, 'client', 'remote'),
            daemon=False
        )
        remote_to_client = threading.Thread(
            target=forward, 
            args=(remote, client, 'remote', 'client'),
            daemon=False
        )
        
        client_to_remote.start()
        remote_to_client.start()
        
        # Wait for both threads to complete
        client_to_remote.join()
        remote_to_client.join()

    def _handle_client_wrapper(self, client, address):
        """Wrapper to manage connection semaphore"""
        with self.conn_lock:
            self.active_connections += 1
            logger.debug(f"Active connections: {self.active_connections}/{self.max_connections}")
        
        try:
            self.handle_client(client, address)
        finally:
            with self.conn_lock:
                self.active_connections -= 1
            self.connection_semaphore.release()

    def start(self):
        # Self-healing: Check and kill old instances
        logger.info("Checking for old instances...")
        self._check_and_kill_old_instances()
        
        # Self-healing: Check and free port if needed
        logger.info("Checking port availability...")
        if not self._check_port_availability():
            logger.error(f"Cannot start: port {self.port} is unavailable")
            sys.exit(1)
        
        # Write PID file
        self._write_pid_file()
        
        # Start server with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server.bind((self.host, self.port))
                self.server.listen(100)
                break
            except Exception as e:
                logger.error(f"Bind attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    logger.info("Retrying in 2 seconds...")
                    time.sleep(2)
                else:
                    logger.error("Failed to start server after all retries")
                    self._cleanup_pid_file()
                    sys.exit(1)
        
        self.running = True
        logger.info("=" * 50)
        logger.info(f"✓ SOCKS5 Proxy started successfully on {self.host}:{self.port}")
        logger.info(f"✓ Username: {self.username}")
        logger.info(f"✓ Max connections: {self.max_connections}")
        logger.info(f"✓ Connection timeout: {CONNECTION_TIMEOUT}s")
        logger.info(f"✓ Idle timeout: {IDLE_TIMEOUT}s")
        logger.info(f"✓ PID: {os.getpid()}")
        logger.info("=" * 50)
        
        try:
            while self.running:
                try:
                    client, address = self.server.accept()
                    
                    # Check if we can accept more connections
                    if not self.connection_semaphore.acquire(blocking=False):
                        logger.warning(f"Max connections reached, rejecting {address}")
                        try:
                            client.close()
                        except Exception:
                            pass
                        continue
                    
                    logger.info(f"Connection from {address}")
                    client_thread = threading.Thread(
                        target=self._handle_client_wrapper,
                        args=(client, address),
                        daemon=False
                    )
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    logger.info("Shutting down...")
                    break
                except Exception as e:
                    logger.error(f"Server error: {e}")
                    if self.running:
                        logger.info("Attempting to recover...")
                        time.sleep(1)
        finally:
            self.running = False
            if self.server:
                try:
                    self.server.close()
                    logger.info("Server closed")
                except Exception:
                    pass
            self._cleanup_pid_file()
            logger.info("Shutdown complete")

if __name__ == '__main__':
    logger.info("=" * 50)
    logger.info("SOCKS5 Proxy Server - Debian 13 Container")
    logger.info("Production-Ready with Self-Healing")
    if HAS_PSUTIL:
        logger.info("✓ psutil available - full self-healing enabled")
    else:
        logger.info("⚠ psutil not available - basic self-healing only")
        logger.info("  (Install with: pip3 install psutil)")
    logger.info("=" * 50)
    
    try:
        proxy = SOCKS5Server(
            PROXY_HOST, 
            PROXY_PORT, 
            PROXY_USER, 
            PROXY_PASS,
            MAX_CONNECTIONS
        )
        proxy.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
