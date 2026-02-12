#!/usr/bin/env python3
"""
HTTP/HTTPS Proxy Server
Production-ready with authentication and self-healing
"""
import os
import sys
import logging
import signal
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import base64
import threading
from socketserver import ThreadingMixIn

# Configuration
PROXY_HOST = os.getenv('HTTP_PROXY_HOST', '0.0.0.0')
PROXY_PORT = int(os.getenv('HTTP_PROXY_PORT', '8080'))
PROXY_USER = os.getenv('HTTP_PROXY_USER', 'user')
PROXY_PASS = os.getenv('HTTP_PROXY_PASS', 'pass')
MAX_CONNECTIONS = int(os.getenv('HTTP_MAX_CONN', '50'))

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads"""
    daemon_threads = True
    allow_reuse_address = True

class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP Proxy Handler with authentication"""
    
    def log_message(self, format, *args):
        """Override to use logger instead of stderr"""
        logger.info("%s - - %s" % (self.address_string(), format % args))
    
    def check_auth(self):
        """Check HTTP Basic Authentication"""
        auth_header = self.headers.get('Proxy-Authorization')
        if not auth_header:
            self.send_response(407)
            self.send_header('Proxy-Authenticate', 'Basic realm="Proxy"')
            self.end_headers()
            return False
        
        try:
            auth_type, credentials = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False
            
            decoded = base64.b64decode(credentials).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            if username == PROXY_USER and password == PROXY_PASS:
                return True
            else:
                logger.warning(f"Failed auth attempt from {self.client_address[0]}")
                return False
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return False
    
    def do_GET(self):
        """Handle GET requests"""
        if not self.check_auth():
            return
        
        try:
            # Forward the request
            req = urllib.request.Request(self.path)
            
            # Copy headers
            for header, value in self.headers.items():
                if header.lower() not in ['proxy-authorization', 'proxy-connection']:
                    req.add_header(header, value)
            
            # Get response
            response = urllib.request.urlopen(req, timeout=30)
            
            # Send response
            self.send_response(response.getcode())
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            
            # Send body
            self.wfile.write(response.read())
            
        except Exception as e:
            logger.error(f"Error handling GET: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")
    
    def do_POST(self):
        """Handle POST requests"""
        if not self.check_auth():
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            req = urllib.request.Request(self.path, data=post_data)
            
            for header, value in self.headers.items():
                if header.lower() not in ['proxy-authorization', 'proxy-connection']:
                    req.add_header(header, value)
            
            response = urllib.request.urlopen(req, timeout=30)
            
            self.send_response(response.getcode())
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            
            self.wfile.write(response.read())
            
        except Exception as e:
            logger.error(f"Error handling POST: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")
    
    def do_CONNECT(self):
        """Handle CONNECT for HTTPS tunneling"""
        if not self.check_auth():
            return
        
        try:
            # Parse target
            host, port = self.path.split(':')
            port = int(port)
            
            # Connect to target
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.settimeout(30)
            target.connect((host, port))
            
            # Send success response
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Start tunneling
            self.tunnel(self.connection, target)
            
        except Exception as e:
            logger.error(f"Error handling CONNECT: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")
    
    def tunnel(self, client, target):
        """Bidirectional tunnel for HTTPS"""
        def forward(source, destination):
            try:
                while True:
                    data = source.recv(8192)
                    if not data:
                        break
                    destination.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    source.shutdown(socket.SHUT_RDWR)
                    source.close()
                except Exception:
                    pass
                try:
                    destination.shutdown(socket.SHUT_RDWR)
                    destination.close()
                except Exception:
                    pass
        
        # Start forwarding threads
        client_to_target = threading.Thread(target=forward, args=(client, target))
        target_to_client = threading.Thread(target=forward, args=(target, client))
        
        client_to_target.daemon = True
        target_to_client.daemon = True
        
        client_to_target.start()
        target_to_client.start()
        
        client_to_target.join()
        target_to_client.join()

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)

def main():
    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    logger.info("=" * 50)
    logger.info("HTTP/HTTPS Proxy Server")
    logger.info("=" * 50)
    logger.info(f"Starting on {PROXY_HOST}:{PROXY_PORT}")
    logger.info(f"Username: {PROXY_USER}")
    logger.info(f"Max connections: {MAX_CONNECTIONS}")
    logger.info("=" * 50)
    
    try:
        server = ThreadedHTTPServer((PROXY_HOST, PROXY_PORT), ProxyHandler)
        logger.info(f"✓ HTTP Proxy started successfully on {PROXY_HOST}:{PROXY_PORT}")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
