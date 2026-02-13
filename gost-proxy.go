package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// Protocol identifiers
	ProtocolSOCKS5      = "socks5"
	ProtocolHTTP        = "http"
	ProtocolShadowsocks = "shadowsocks"
	ProtocolUnknown     = "unknown"

	// SOCKS5 constants
	SOCKS5Version      = 0x05
	SOCKS5AuthNone     = 0x00
	SOCKS5AuthPassword = 0x02
	SOCKS5AuthNoMethod = 0xFF
	SOCKS5CmdConnect   = 0x01
	SOCKS5AtypIPv4     = 0x01
	SOCKS5AtypDomain   = 0x03
	SOCKS5AtypIPv6     = 0x04

	// SOCKS5 reply codes
	SOCKS5RepSuccess          = 0x00
	SOCKS5RepGeneralFailure   = 0x01
	SOCKS5RepNotAllowed       = 0x02
	SOCKS5RepNetUnreachable   = 0x03
	SOCKS5RepHostUnreachable  = 0x04
	SOCKS5RepConnRefused      = 0x05
	SOCKS5RepTTLExpired       = 0x06
	SOCKS5RepCmdNotSupported  = 0x07
	SOCKS5RepAtypNotSupported = 0x08

	// Buffer sizes
	BufferSize     = 32 * 1024
	PeekBufferSize = 16
)

// Config holds server configuration
type Config struct {
	Host              string
	Port              int
	Username          string
	Password          string
	ShadowsocksKey    string
	ShadowsocksCipher string
	MaxConnections    int
	HandshakeTimeout  time.Duration
	ConnectionTimeout time.Duration
	IdleTimeout       time.Duration
	AuthFailLimit     int
	AuthFailWindow    time.Duration
	AllowNoAuth       bool
	ForceIPv4         bool
}

// Server represents the multi-protocol proxy server
type Server struct {
	config        *Config
	listener      net.Listener
	activeConns   int64
	connSemaphore chan struct{}
	authFailures  map[string][]time.Time
	authMutex     sync.RWMutex
	shutdown      chan struct{}
	wg            sync.WaitGroup
	running       atomic.Bool
}

// ConnectionWrapper wraps a connection with a buffered reader for protocol detection
type ConnectionWrapper struct {
	net.Conn
	reader *bufio.Reader
}

func NewConnectionWrapper(conn net.Conn) *ConnectionWrapper {
	return &ConnectionWrapper{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (w *ConnectionWrapper) Read(p []byte) (n int, err error) {
	return w.reader.Read(p)
}

func (w *ConnectionWrapper) Peek(n int) ([]byte, error) {
	return w.reader.Peek(n)
}

// NewServer creates a new multi-protocol proxy server
func NewServer(config *Config) *Server {
	return &Server{
		config:        config,
		connSemaphore: make(chan struct{}, config.MaxConnections),
		authFailures:  make(map[string][]time.Time),
		shutdown:      make(chan struct{}),
	}
}

// Start begins listening and accepting connections
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind %s: %w", addr, err)
	}

	s.listener = ln
	s.running.Store(true)

	log.Printf("Multi-protocol proxy listening on %s", addr)
	log.Printf("Max connections: %d", s.config.MaxConnections)

	protocols := "SOCKS5, HTTP CONNECT"
	if s.config.ShadowsocksKey != "" {
		protocols += fmt.Sprintf(", Shadowsocks (%s)", s.config.ShadowsocksCipher)
	}
	if s.config.AllowNoAuth {
		protocols += " (no-auth allowed)"
	}
	log.Printf("Protocols: %s", protocols)

	// Handle graceful shutdown
	go s.handleSignals()

	// Accept loop
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.Printf("Accept error: %v", err)
				continue
			}
			break
		}

		// Apply connection limit
		select {
		case s.connSemaphore <- struct{}{}:
			s.wg.Add(1)
			atomic.AddInt64(&s.activeConns, 1)
			go s.handleConnection(conn)
		default:
			log.Printf("Connection limit reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
		}
	}

	return nil
}

// handleSignals handles graceful shutdown
func (s *Server) handleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal %v, initiating graceful shutdown", sig)

	s.running.Store(false)
	close(s.shutdown)

	if s.listener != nil {
		s.listener.Close()
	}

	// Wait up to 30 seconds for connections to complete
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("All connections closed gracefully")
	case <-time.After(30 * time.Second):
		active := atomic.LoadInt64(&s.activeConns)
		log.Printf("Force shutdown with %d active connections", active)
	}

	os.Exit(0)
}

// handleConnection handles a new connection with protocol detection
func (s *Server) handleConnection(rawConn net.Conn) {
	defer func() {
		rawConn.Close()
		<-s.connSemaphore
		atomic.AddInt64(&s.activeConns, -1)
		s.wg.Done()
	}()

	// Set read deadline for protocol detection
	rawConn.SetReadDeadline(time.Now().Add(s.config.HandshakeTimeout))

	// Wrap connection for peeking
	conn := NewConnectionWrapper(rawConn)

	// Detect protocol
	protocol, err := s.detectProtocol(conn)
	if err != nil {
		// Many mobile apps probe by opening and closing quickly; don't treat early EOF as failure.
		if errors.Is(err, io.EOF) {
			return
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Protocol detection timeout from %s after %s", conn.RemoteAddr(), s.config.HandshakeTimeout)
			return
		}
		log.Printf("Protocol detection failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Reset deadline
	conn.SetReadDeadline(time.Now().Add(s.config.ConnectionTimeout))

	// Route to appropriate handler
	switch protocol {
	case ProtocolSOCKS5:
		s.handleSOCKS5(conn)
	case ProtocolHTTP:
		s.handleHTTP(conn)
	case ProtocolShadowsocks:
		// Use wrapped connection so bytes buffered by detectProtocol Peek() are preserved.
		s.handleShadowsocks(conn)
	default:
		log.Printf("Unknown protocol from %s", conn.RemoteAddr())
	}
}

// detectProtocol determines the protocol from initial bytes
func (s *Server) detectProtocol(conn *ConnectionWrapper) (string, error) {
	// Peek just one byte first so SOCKS5 clients that send short greetings
	// are detected immediately without blocking for larger peeks.
	first, err := conn.Peek(1)
	if err != nil {
		return ProtocolUnknown, err
	}
	if len(first) > 0 && first[0] == SOCKS5Version {
		return ProtocolSOCKS5, nil
	}

	// Try to peek a small HTTP prefix; tolerate short reads.
	data, err := conn.Peek(5)
	if err != nil && !errors.Is(err, io.EOF) {
		return ProtocolUnknown, err
	}

	methods := []string{"GET ", "POST ", "PUT ", "DELE", "HEAD ", "OPTI", "PATC", "CONN"}
	dataStr := strings.ToUpper(string(data))
	for _, method := range methods {
		if strings.HasPrefix(dataStr, method) || strings.HasPrefix(method, dataStr) {
			return ProtocolHTTP, nil
		}
	}

	// Check for Shadowsocks (encrypted data, no clear pattern)
	// If not SOCKS5 or HTTP, try Shadowsocks if key is configured
	if s.config.ShadowsocksKey != "" {
		return ProtocolShadowsocks, nil
	}

	return ProtocolUnknown, nil
}

// checkRateLimit checks if an IP has exceeded auth failure rate limit
func (s *Server) checkRateLimit(ip string) bool {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-s.config.AuthFailWindow)

	// Clean old entries
	failures := s.authFailures[ip]
	validFailures := make([]time.Time, 0)
	for _, t := range failures {
		if t.After(cutoff) {
			validFailures = append(validFailures, t)
		}
	}
	s.authFailures[ip] = validFailures

	allowed := len(validFailures) < s.config.AuthFailLimit
	if !allowed {
		log.Printf("Rate limit exceeded for %s", ip)
	}
	return allowed
}

// recordAuthFailure records an authentication failure
func (s *Server) recordAuthFailure(ip string) {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()

	s.authFailures[ip] = append(s.authFailures[ip], time.Now())
}

// handleSOCKS5 handles SOCKS5 protocol
func (s *Server) handleSOCKS5(conn *ConnectionWrapper) {
	clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	// Read greeting: version and methods
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}

	version := greeting[0]
	nmethods := greeting[1]

	if version != SOCKS5Version {
		return
	}

	// Read methods
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Select authentication method
	var selectedMethod byte = SOCKS5AuthNoMethod
	hasPasswordAuth := false
	hasNoAuth := false

	for _, m := range methods {
		if m == SOCKS5AuthPassword {
			hasPasswordAuth = true
		}
		if m == SOCKS5AuthNone {
			hasNoAuth = true
		}
	}

	if hasPasswordAuth {
		selectedMethod = SOCKS5AuthPassword
	} else if s.config.AllowNoAuth && hasNoAuth {
		selectedMethod = SOCKS5AuthNone
	}

	// Send method selection
	if _, err := conn.Write([]byte{SOCKS5Version, selectedMethod}); err != nil {
		return
	}

	if selectedMethod == SOCKS5AuthNoMethod {
		log.Printf("No compatible auth method from %s", clientIP)
		return
	}

	// Handle authentication
	if selectedMethod == SOCKS5AuthPassword {
		if !s.authenticateSOCKS5(conn, clientIP) {
			return
		}
	} else {
		log.Printf("Accepted no-auth SOCKS5 from %s", clientIP)
	}

	// Read request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	atyp := reqHeader[3]

	if cmd != SOCKS5CmdConnect {
		s.sendSOCKS5Reply(conn, SOCKS5RepCmdNotSupported)
		return
	}

	// Parse destination address
	var host string
	var err error

	switch atyp {
	case SOCKS5AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()

	case SOCKS5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainLen := lenBuf[0]
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)

	case SOCKS5AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()

	default:
		s.sendSOCKS5Reply(conn, SOCKS5RepAtypNotSupported)
		return
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Connect to target
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var remote net.Conn
	if !s.isSafeTarget(host) {
		log.Printf("Blocked unsafe SOCKS5 target from %s to %s", clientIP, target)
		s.sendSOCKS5Reply(conn, SOCKS5RepNotAllowed)
		return
	}

	if s.config.ForceIPv4 {
		remote, err = s.dialIPv4(target, s.config.ConnectionTimeout)
	} else {
		remote, err = net.DialTimeout("tcp", target, s.config.ConnectionTimeout)
	}

	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.sendSOCKS5Reply(conn, SOCKS5RepTTLExpired)
		} else {
			s.sendSOCKS5Reply(conn, SOCKS5RepHostUnreachable)
		}
		return
	}
	defer remote.Close()

	// Send success reply
	bindAddr := remote.LocalAddr().(*net.TCPAddr)
	reply := s.buildSOCKS5Reply(SOCKS5RepSuccess, bindAddr)
	if _, err := conn.Write(reply); err != nil {
		return
	}

	log.Printf("%s connected to %s", clientIP, target)

	// Set idle timeout and relay
	conn.SetDeadline(time.Now().Add(s.config.IdleTimeout))
	remote.SetDeadline(time.Now().Add(s.config.IdleTimeout))
	s.relay(conn, remote)
}

// authenticateSOCKS5 performs SOCKS5 username/password authentication
func (s *Server) authenticateSOCKS5(conn *ConnectionWrapper, clientIP string) bool {
	// Check rate limit
	if !s.checkRateLimit(clientIP) {
		conn.Write([]byte{0x01, 0x01}) // Auth version 1, status failure
		return false
	}

	// Read auth request
	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHeader); err != nil {
		return false
	}

	authVersion := authHeader[0]
	userLen := authHeader[1]

	if authVersion != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return false
	}

	// Read username
	username := make([]byte, userLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return false
	}

	// Read password length
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return false
	}

	// Read password
	password := make([]byte, passLenBuf[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return false
	}

	// Verify credentials using constant-time comparison
	userMatch := subtle.ConstantTimeCompare(username, []byte(s.config.Username)) == 1
	passMatch := subtle.ConstantTimeCompare(password, []byte(s.config.Password)) == 1

	if !userMatch || !passMatch {
		s.recordAuthFailure(clientIP)
		conn.Write([]byte{0x01, 0x01}) // Auth failure
		log.Printf("Auth failed from %s", clientIP)
		return false
	}

	// Auth success
	conn.Write([]byte{0x01, 0x00})
	return true
}

// sendSOCKS5Reply sends a SOCKS5 reply with the given status
func (s *Server) sendSOCKS5Reply(conn net.Conn, rep byte) {
	reply := []byte{SOCKS5Version, rep, 0x00, SOCKS5AtypIPv4, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}

// buildSOCKS5Reply builds a SOCKS5 success reply with bind address
func (s *Server) buildSOCKS5Reply(rep byte, bindAddr *net.TCPAddr) []byte {
	reply := []byte{SOCKS5Version, rep, 0x00}

	if ip4 := bindAddr.IP.To4(); ip4 != nil {
		reply = append(reply, SOCKS5AtypIPv4)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, SOCKS5AtypIPv6)
		reply = append(reply, bindAddr.IP...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(bindAddr.Port))
	reply = append(reply, portBuf...)

	return reply
}

// handleHTTP handles HTTP CONNECT method
func (s *Server) handleHTTP(conn *ConnectionWrapper) {
	clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	// Read HTTP request line
	reader := bufio.NewReader(conn.reader)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		s.sendHTTPError(conn, 400, "Bad Request")
		return
	}

	method := parts[0]
	target := parts[1]

	// Only support CONNECT method
	if method != "CONNECT" {
		s.sendHTTPError(conn, 405, "Method Not Allowed")
		return
	}

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			headers[strings.ToLower(key)] = value
		}
	}

	// Check authentication
	if !s.authenticateHTTP(headers, clientIP) {
		s.sendHTTPAuthRequired(conn)
		return
	}

	// Parse target host:port
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		s.sendHTTPError(conn, 400, "Bad Request")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.sendHTTPError(conn, 400, "Invalid Port")
		return
	}

	// Block certain ports
	blockedPorts := map[int]bool{22: true, 23: true, 25: true, 3306: true, 5432: true, 6379: true, 27017: true}
	if blockedPorts[port] {
		s.sendHTTPError(conn, 403, "Port Not Allowed")
		return
	}
	if !s.isSafeTarget(host) {
		s.sendHTTPError(conn, 403, "Target Not Allowed")
		return
	}

	// Connect to target
	targetAddr := net.JoinHostPort(host, portStr)
	var remote net.Conn

	if s.config.ForceIPv4 {
		remote, err = s.dialIPv4(targetAddr, s.config.ConnectionTimeout)
	} else {
		remote, err = net.DialTimeout("tcp", targetAddr, s.config.ConnectionTimeout)
	}

	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		s.sendHTTPError(conn, 502, "Bad Gateway")
		return
	}
	defer remote.Close()

	// Send success response
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	log.Printf("%s connected to %s via HTTP", clientIP, targetAddr)

	// Set idle timeout and relay
	conn.SetDeadline(time.Now().Add(s.config.IdleTimeout))
	remote.SetDeadline(time.Now().Add(s.config.IdleTimeout))
	s.relay(conn, remote)
}

// authenticateHTTP verifies HTTP proxy authentication
func (s *Server) authenticateHTTP(headers map[string]string, clientIP string) bool {
	// Check rate limit
	if !s.checkRateLimit(clientIP) {
		return false
	}

	authHeader := headers["proxy-authorization"]
	if authHeader == "" {
		return false
	}

	// Parse Basic authentication
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "basic" {
		s.recordAuthFailure(clientIP)
		return false
	}

	// Decode credentials
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		s.recordAuthFailure(clientIP)
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		s.recordAuthFailure(clientIP)
		return false
	}

	// Constant-time comparison
	userMatch := subtle.ConstantTimeCompare([]byte(credentials[0]), []byte(s.config.Username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(credentials[1]), []byte(s.config.Password)) == 1

	if !userMatch || !passMatch {
		s.recordAuthFailure(clientIP)
		log.Printf("HTTP auth failed from %s", clientIP)
		return false
	}

	return true
}

// sendHTTPError sends an HTTP error response
func (s *Server) sendHTTPError(conn net.Conn, code int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, message)
	conn.Write([]byte(response))
}

// sendHTTPAuthRequired sends HTTP 407 Proxy Authentication Required
func (s *Server) sendHTTPAuthRequired(conn net.Conn) {
	response := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(response))
}

// isSafeTarget blocks loopback, private, and link-local destinations.
func (s *Server) isSafeTarget(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return !(addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast())
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		log.Printf("Target DNS lookup failed for %s: %v", host, err)
		return false
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			return false
		}
	}
	return true
}

// dialIPv4 dials a connection forcing IPv4
func (s *Server) dialIPv4(address string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, addr := range addrs {
		if addr.To4() != nil {
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort(addr.String(), port), timeout)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no IPv4 address found")
}

// relay bidirectionally relays data between two connections
func (s *Server) relay(conn1, conn2 net.Conn) {
	done := make(chan error, 2)

	copyData := func(dst, src net.Conn) {
		buf := make([]byte, BufferSize)
		_, err := io.CopyBuffer(dst, src, buf)
		done <- err
	}

	go copyData(conn1, conn2)
	go copyData(conn2, conn1)

	// Wait for one direction to finish
	<-done

	// Close both connections to terminate the other direction
	conn1.Close()
	conn2.Close()

	// Wait for second direction
	<-done
}

// Shadowsocks AEAD Cipher implementation
type ShadowsocksCipher struct {
	key    []byte
	cipher string
}

func NewShadowsocksCipher(password, method string) (*ShadowsocksCipher, error) {
	var keySize int
	switch method {
	case "aes-128-gcm":
		keySize = 16
	case "aes-256-gcm":
		keySize = 32
	case "chacha20-ietf-poly1305":
		keySize = 32
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", method)
	}

	key := evpBytesToKey(password, keySize)
	return &ShadowsocksCipher{
		key:    key,
		cipher: method,
	}, nil
}

// evpBytesToKey derives a key from password (OpenSSL EVP_BytesToKey)
func evpBytesToKey(password string, keyLen int) []byte {
	const md5Len = 16
	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, MD5Sum([]byte(password)))

	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], MD5Sum(d))
	}
	return m[:keyLen]
}

func MD5Sum(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

// HKDF-SHA1 key derivation for AEAD ciphers
func hkdfSHA1(secret, salt, info []byte, keyLen int) ([]byte, error) {
	r := hkdf.New(sha1.New, secret, salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// newAEAD creates an AEAD cipher from salt
func (sc *ShadowsocksCipher) newAEAD(salt []byte) (cipher.AEAD, error) {
	subkey, err := hkdfSHA1(sc.key, salt, []byte("ss-subkey"), len(sc.key))
	if err != nil {
		return nil, err
	}

	switch sc.cipher {
	case "aes-128-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-ietf-poly1305":
		return nil, fmt.Errorf("chacha20-poly1305 not implemented in minimal version")
	default:
		return nil, fmt.Errorf("unsupported cipher: %s", sc.cipher)
	}
}

func (sc *ShadowsocksCipher) getSaltSize() int {
	switch sc.cipher {
	case "aes-128-gcm":
		return 16
	case "aes-256-gcm":
		return 32
	case "chacha20-ietf-poly1305":
		return 32
	default:
		return 32
	}
}

// ShadowsocksConn wraps a connection with AEAD encryption/decryption
type ShadowsocksConn struct {
	net.Conn
	readAEAD   cipher.AEAD
	writeAEAD  cipher.AEAD
	readBuf    []byte
	writeBuf   []byte
	readNonce  []byte
	writeNonce []byte
}

func (sc *ShadowsocksCipher) wrapConn(conn net.Conn) (*ShadowsocksConn, error) {
	saltSize := sc.getSaltSize()

	// Read salt from client
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, fmt.Errorf("failed to read client salt: %w", err)
	}

	readAEAD, err := sc.newAEAD(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to create read AEAD: %w", err)
	}

	// Generate random salt for writing
	writeSalt := make([]byte, saltSize)
	if _, err := rand.Read(writeSalt); err != nil {
		return nil, fmt.Errorf("failed to generate write salt: %w", err)
	}

	writeAEAD, err := sc.newAEAD(writeSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to create write AEAD: %w", err)
	}

	// Send salt to client
	if _, err := conn.Write(writeSalt); err != nil {
		return nil, fmt.Errorf("failed to send write salt: %w", err)
	}

	return &ShadowsocksConn{
		Conn:       conn,
		readAEAD:   readAEAD,
		writeAEAD:  writeAEAD,
		readNonce:  make([]byte, readAEAD.NonceSize()),
		writeNonce: make([]byte, writeAEAD.NonceSize()),
		readBuf:    make([]byte, 0, 0x3FFF+readAEAD.Overhead()), // Pre-allocate buffer
		writeBuf:   make([]byte, 0, 0x3FFF+writeAEAD.Overhead()),
	}, nil
}

func (c *ShadowsocksConn) Read(b []byte) (n int, err error) {
	// Serve buffered plaintext first if available.
	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read length (2 bytes encrypted + tag)
	lenCipher := make([]byte, 2+c.readAEAD.Overhead())
	if _, err := io.ReadFull(c.Conn, lenCipher); err != nil {
		return 0, fmt.Errorf("failed to read length header: %w", err)
	}

	// Decrypt length
	lengthBuf, err := c.readAEAD.Open(nil, c.readNonce, lenCipher, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt length: %w", err)
	}
	increment(c.readNonce)

	payloadLen := binary.BigEndian.Uint16(lengthBuf)
	if payloadLen > 0x3FFF {
		return 0, fmt.Errorf("payload length too large: %d", payloadLen)
	}

	// Read encrypted payload
	payloadCipher := make([]byte, int(payloadLen)+c.readAEAD.Overhead())
	if _, err := io.ReadFull(c.Conn, payloadCipher); err != nil {
		return 0, fmt.Errorf("failed to read payload: %w", err)
	}

	// Decrypt payload
	payload, err := c.readAEAD.Open(nil, c.readNonce, payloadCipher, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	increment(c.readNonce)

	// Buffer full plaintext chunk; return as much as caller requested.
	c.readBuf = append(c.readBuf[:0], payload...)
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *ShadowsocksConn) Write(b []byte) (n int, err error) {
	// Shadowsocks AEAD: length (2 bytes) || payload
	// Both encrypted separately with tags

	for len(b) > 0 {
		// Max chunk size (0x3FFF = 16383)
		payloadLen := len(b)
		if payloadLen > 0x3FFF {
			payloadLen = 0x3FFF
		}

		// Encrypt length
		lengthBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuf, uint16(payloadLen))
		encLength := c.writeAEAD.Seal(nil, c.writeNonce, lengthBuf, nil)
		increment(c.writeNonce)

		// Encrypt payload
		encPayload := c.writeAEAD.Seal(nil, c.writeNonce, b[:payloadLen], nil)
		increment(c.writeNonce)

		// Write both
		if _, err := c.Conn.Write(encLength); err != nil {
			return n, fmt.Errorf("failed to write encrypted length: %w", err)
		}
		if _, err := c.Conn.Write(encPayload); err != nil {
			return n, fmt.Errorf("failed to write encrypted payload: %w", err)
		}

		n += payloadLen
		b = b[payloadLen:]
	}

	return n, nil
}

func increment(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// handleShadowsocks handles Shadowsocks protocol.
func (s *Server) handleShadowsocks(conn net.Conn) {
	clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	// Create cipher
	cipher, err := NewShadowsocksCipher(s.config.ShadowsocksKey, s.config.ShadowsocksCipher)
	if err != nil {
		log.Printf("Failed to create Shadowsocks cipher: %v", err)
		return
	}

	// Wrap connection with encryption
	ssConn, err := cipher.wrapConn(conn)
	if err != nil {
		log.Printf("Failed to wrap Shadowsocks connection from %s: %v", clientIP, err)
		return
	}

	// Read target address (SOCKS5-like format)
	addrBuf := make([]byte, 1)
	if _, err := ssConn.Read(addrBuf); err != nil {
		log.Printf("Shadowsocks: Failed to read address type from %s: %v", clientIP, err)
		return
	}

	atyp := addrBuf[0]
	var host string
	var port uint16

	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(ssConn, addr); err != nil {
			log.Printf("Shadowsocks: Failed to read IPv4 from %s: %v", clientIP, err)
			return
		}
		host = net.IP(addr).String()

	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := ssConn.Read(lenBuf); err != nil {
			log.Printf("Shadowsocks: Failed to read domain length from %s: %v", clientIP, err)
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(ssConn, domain); err != nil {
			log.Printf("Shadowsocks: Failed to read domain from %s: %v", clientIP, err)
			return
		}
		host = string(domain)

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(ssConn, addr); err != nil {
			log.Printf("Shadowsocks: Failed to read IPv6 from %s: %v", clientIP, err)
			return
		}
		host = net.IP(addr).String()

	default:
		log.Printf("Shadowsocks: Unsupported address type 0x%02x from %s", atyp, clientIP)
		return
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(ssConn, portBuf); err != nil {
		log.Printf("Shadowsocks: Failed to read port from %s: %v", clientIP, err)
		return
	}
	port = binary.BigEndian.Uint16(portBuf)

	// Connect to target
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if !s.isSafeTarget(host) {
		log.Printf("Blocked unsafe Shadowsocks target from %s to %s", clientIP, target)
		return
	}

	var remote net.Conn
	if s.config.ForceIPv4 {
		remote, err = s.dialIPv4(target, s.config.ConnectionTimeout)
	} else {
		remote, err = net.DialTimeout("tcp", target, s.config.ConnectionTimeout)
	}

	if err != nil {
		log.Printf("Shadowsocks: Failed to connect to %s: %v", target, err)
		return
	}
	defer remote.Close()

	log.Printf("%s connected to %s via Shadowsocks", clientIP, target)

	// Set timeouts and relay
	ssConn.SetDeadline(time.Now().Add(s.config.IdleTimeout))
	remote.SetDeadline(time.Now().Add(s.config.IdleTimeout))
	s.relay(ssConn, remote)
}

func getEnvInt(name string, defaultVal, min, max int) int {
	val := os.Getenv(name)
	if val == "" {
		return defaultVal
	}

	num, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("%s=%s is invalid, using default %d", name, val, defaultVal)
		return defaultVal
	}

	if num < min || num > max {
		log.Printf("%s=%d out of range [%d, %d], using default %d", name, num, min, max, defaultVal)
		return defaultVal
	}

	return num
}

// getEnvBool gets a boolean from environment
func getEnvBool(name string, defaultVal bool) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if val == "" {
		return defaultVal
	}
	return val == "1" || val == "true" || val == "yes" || val == "on"
}

func main() {
	// Load configuration from environment
	config := &Config{
		Host:              os.Getenv("GOST_HOST"),
		Port:              getEnvInt("GOST_PORT", 8080, 1, 65535),
		Username:          os.Getenv("GOST_USER"),
		Password:          os.Getenv("GOST_PASS"),
		ShadowsocksKey:    os.Getenv("GOST_SS_KEY"),
		ShadowsocksCipher: os.Getenv("GOST_SS_CIPHER"),
		MaxConnections:    getEnvInt("GOST_MAX_CONN", 200, 1, 10000),
		HandshakeTimeout:  time.Duration(getEnvInt("GOST_HANDSHAKE_TIMEOUT", 30, 5, 300)) * time.Second,
		ConnectionTimeout: time.Duration(getEnvInt("GOST_TIMEOUT", 15, 3, 300)) * time.Second,
		IdleTimeout:       time.Duration(getEnvInt("GOST_IDLE_TIMEOUT", 300, 5, 86400)) * time.Second,
		AuthFailLimit:     getEnvInt("GOST_AUTH_FAIL_LIMIT", 5, 1, 100),
		AuthFailWindow:    time.Duration(getEnvInt("GOST_AUTH_FAIL_WINDOW", 60, 1, 3600)) * time.Second,
		AllowNoAuth:       getEnvBool("GOST_ALLOW_NOAUTH", false),
		ForceIPv4:         getEnvBool("GOST_FORCE_IPV4", true),
	}

	// Set default Shadowsocks cipher if key provided but cipher not specified
	if config.ShadowsocksKey != "" && config.ShadowsocksCipher == "" {
		config.ShadowsocksCipher = "aes-256-gcm"
	}

	// Validate required config
	if config.Username == "" || config.Password == "" {
		log.Fatal("GOST_USER and GOST_PASS must be set")
	}

	if config.Host == "" {
		config.Host = "0.0.0.0"
	}

	// Create and start server
	server := NewServer(config)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
