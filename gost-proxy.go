package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
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

	// appVersion is reported by -version.
	appVersion = "1.1.0"

	// maxHTTPHeaderBytes caps the request line + header block a client may
	// send before the connection is dropped (memory-DoS guard).
	maxHTTPHeaderBytes = 8 * 1024

	// maxAuthFailureEntries bounds the per-IP auth failure map.
	maxAuthFailureEntries = 10000

	// replayCacheSize bounds the Shadowsocks replay filter; replayWindow is
	// how long a used salt is remembered (salt reuse is only attempted by
	// replaying attackers — legitimate clients generate fresh ones).
	replayCacheSize = 100000
	replayWindow    = 24 * time.Hour
)

// errBlockedTarget marks egress-policy rejections in resolveTarget errors.
var errBlockedTarget = errors.New("target blocked by egress policy")

// cgnatPrefix is the shared CGNAT space (RFC 6598), treated as internal.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// blockedTargetPorts are egress ports never proxied to, on every protocol.
var blockedTargetPorts = map[int]bool{
	22:    true, // SSH
	23:    true, // Telnet
	25:    true, // SMTP (outbound spam relay)
	3306:  true, // MySQL
	5432:  true, // PostgreSQL
	6379:  true, // Redis
	27017: true, // MongoDB
}

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
	SniffTimeout      time.Duration
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
	replay        *replayCache
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

// CloseWrite half-closes the underlying connection when it supports it, so a
// finished direction of a relay can signal EOF without killing the other.
func (w *ConnectionWrapper) CloseWrite() error {
	if cw, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return w.Conn.Close()
}

// NewServer creates a new multi-protocol proxy server
func NewServer(config *Config) *Server {
	return &Server{
		config:        config,
		connSemaphore: make(chan struct{}, config.MaxConnections),
		authFailures:  make(map[string][]time.Time),
		replay:        newReplayCache(replayCacheSize),
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

	// Warn once about plaintext credentials on the wire
	log.Println("NOTE: SOCKS5/HTTP auth credentials are sent without encryption; use the tlsgost image or a TLS terminator in front of this proxy")

	// Handle graceful shutdown
	go s.handleSignals()

	// Accept loop
	acceptFails := 0
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				acceptFails++
				log.Printf("Accept error: %v", err)
				// Back off so a persistent accept failure (e.g. fd
				// exhaustion) does not spin CPU and flood the log.
				backoff := time.Duration(acceptFails) * 10 * time.Millisecond
				if backoff > time.Second {
					backoff = time.Second
				}
				time.Sleep(backoff)
				continue
			}
			break
		}
		acceptFails = 0

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

	// Set read deadline for protocol detection. This runs before any
	// authentication, so it uses the shorter sniff timeout to limit how long
	// an unauthenticated client can hold a connection slot with a slow drip.
	rawConn.SetReadDeadline(time.Now().Add(s.config.SniffTimeout))

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
			log.Printf("Protocol detection timeout from %s after %s", conn.RemoteAddr(), s.config.SniffTimeout)
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

	// Clean old entries; delete the key entirely once empty so the map
	// cannot grow forever under rotating/spoofed source IPs.
	failures := s.authFailures[ip]
	validFailures := make([]time.Time, 0)
	for _, t := range failures {
		if t.After(cutoff) {
			validFailures = append(validFailures, t)
		}
	}
	if len(validFailures) == 0 {
		delete(s.authFailures, ip)
		return true
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

	// Bound total tracked IPs; evict an arbitrary entry when full rather
	// than letting the map grow without limit.
	if _, ok := s.authFailures[ip]; !ok && len(s.authFailures) >= maxAuthFailureEntries {
		for k := range s.authFailures {
			delete(s.authFailures, k)
			break
		}
	}

	s.authFailures[ip] = append(s.authFailures[ip], time.Now())
}

// extractIP returns the host part of a remote address, handling IPv6.
func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// sanitizeLog strips control characters from client-supplied strings so a
// malicious target host cannot forge log lines (newline injection).
func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// errHeaderTooLarge is returned when the HTTP header block exceeds the cap.
var errHeaderTooLarge = errors.New("header section too large")

// readHTTPLine reads one CRLF/LF-terminated line directly from the wrapper's
// buffered reader, enforcing a shared byte budget across the whole header
// block. Byte-by-byte reads on the buffered reader are cheap and guarantee no
// pipelined tunnel bytes are swallowed into a second buffer.
func readHTTPLine(r *bufio.Reader, budget *int) (string, error) {
	var sb strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		*budget--
		if *budget < 0 {
			return "", errHeaderTooLarge
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
	}
}

// replayCache is a bounded seen-salt filter rejecting replayed Shadowsocks
// handshakes.
type replayCache struct {
	mu    sync.Mutex
	salts map[[32]byte]time.Time
	max   int
}

func newReplayCache(max int) *replayCache {
	return &replayCache{salts: make(map[[32]byte]time.Time), max: max}
}

// checkOrAdd returns false if the salt was seen before (replay).
func (r *replayCache) checkOrAdd(salt []byte) bool {
	var key [32]byte
	copy(key[:], salt)

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.salts) >= r.max {
		now := time.Now()
		for k, t := range r.salts {
			if now.Sub(t) > replayWindow {
				delete(r.salts, k)
			}
		}
		// Still full: evict an arbitrary entry to stay bounded.
		if len(r.salts) >= r.max {
			for k := range r.salts {
				delete(r.salts, k)
				break
			}
		}
	}

	if _, seen := r.salts[key]; seen {
		return false
	}
	r.salts[key] = time.Now()
	return true
}

// handleSOCKS5 handles SOCKS5 protocol
func (s *Server) handleSOCKS5(conn *ConnectionWrapper) {
	clientIP := extractIP(conn.RemoteAddr())

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

	// Connect to target. The egress port policy applies to every protocol
	// (HTTP CONNECT included) so the proxy cannot be abused e.g. for SMTP
	// spam relay over SOCKS5.
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if blockedTargetPorts[int(port)] {
		log.Printf("Blocked SOCKS5 egress port %d from %s to %s", port, clientIP, sanitizeLog(target))
		s.sendSOCKS5Reply(conn, SOCKS5RepNotAllowed)
		return
	}

	// Resolve and validate once, then dial the validated IP literally —
	// re-resolving here would open a DNS-rebinding TOCTOU window.
	addrs, err := s.resolveTarget(host)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			log.Printf("Blocked unsafe SOCKS5 target from %s to %s", clientIP, sanitizeLog(target))
			s.sendSOCKS5Reply(conn, SOCKS5RepNotAllowed)
		} else {
			log.Printf("Failed to resolve SOCKS5 target %s from %s: %v", sanitizeLog(host), clientIP, err)
			s.sendSOCKS5Reply(conn, SOCKS5RepHostUnreachable)
		}
		return
	}

	remote, err := s.dialTarget(addrs, int(port))
	if err != nil {
		log.Printf("Failed to connect to %s: %v", sanitizeLog(target), err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			s.sendSOCKS5Reply(conn, SOCKS5RepTTLExpired)
		} else {
			s.sendSOCKS5Reply(conn, SOCKS5RepHostUnreachable)
		}
		return
	}
	defer remote.Close()

	// Send success reply
	bindAddr, _ := remote.LocalAddr().(*net.TCPAddr)
	if bindAddr == nil {
		bindAddr = &net.TCPAddr{}
	}
	reply := s.buildSOCKS5Reply(SOCKS5RepSuccess, bindAddr)
	if _, err := conn.Write(reply); err != nil {
		return
	}

	log.Printf("%s connected to %s", clientIP, sanitizeLog(target))

	s.relay(newIdleConn(conn, s.config.IdleTimeout), newIdleConn(remote, s.config.IdleTimeout))
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
	clientIP := extractIP(conn.RemoteAddr())

	// Read the request line and headers directly from the wrapper's buffered
	// reader under a hard byte cap. Reading from conn.reader (not a second
	// bufio wrapper) preserves bytes pipelined after the headers for the
	// tunnel, and the budget stops multi-GB header flooding.
	budget := maxHTTPHeaderBytes
	requestLine, err := readHTTPLine(conn.reader, &budget)
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
		line, err := readHTTPLine(conn.reader, &budget)
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

	// Block certain ports (same policy on all protocols)
	if blockedTargetPorts[port] {
		s.sendHTTPError(conn, 403, "Port Not Allowed")
		return
	}

	// Resolve and validate once, then dial the validated IP literally.
	addrs, err := s.resolveTarget(host)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			log.Printf("Blocked unsafe HTTP target from %s to %s", clientIP, sanitizeLog(target))
			s.sendHTTPError(conn, 403, "Target Not Allowed")
		} else {
			log.Printf("Failed to resolve HTTP target %s from %s: %v", sanitizeLog(host), clientIP, err)
			s.sendHTTPError(conn, 502, "Bad Gateway")
		}
		return
	}

	targetAddr := net.JoinHostPort(host, portStr)
	remote, err := s.dialTarget(addrs, port)

	if err != nil {
		log.Printf("Failed to connect to %s: %v", sanitizeLog(targetAddr), err)
		s.sendHTTPError(conn, 502, "Bad Gateway")
		return
	}
	defer remote.Close()

	// Send success response
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	log.Printf("%s connected to %s via HTTP", clientIP, sanitizeLog(targetAddr))

	s.relay(newIdleConn(conn, s.config.IdleTimeout), newIdleConn(remote, s.config.IdleTimeout))
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

// isBlockedIP reports whether addr is a non-public destination: loopback,
// private, link-local, multicast, unspecified (0.0.0.0/:: — on Linux, dialing
// 0.0.0.0 reaches loopback services), or CGNAT shared space.
func isBlockedIP(addr netip.Addr) bool {
	return addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() ||
		addr.IsMulticast() ||
		cgnatPrefix.Contains(addr)
}

// resolveTarget resolves host once and validates every returned address
// against the egress policy. Callers MUST dial the returned addresses
// directly (never re-resolve the hostname) or the validation is vulnerable
// to DNS-rebinding TOCTOU.
func (s *Server) resolveTarget(host string) ([]netip.Addr, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return nil, errBlockedTarget
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedIP(addr) {
			return nil, errBlockedTarget
		}
		return []netip.Addr{addr}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.ConnectionTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("target DNS lookup failed for %s: %w", sanitizeLog(host), err)
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		if isBlockedIP(addr) {
			return nil, errBlockedTarget
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, errors.New("no usable addresses for target")
	}
	return addrs, nil
}

// dialTarget dials pre-validated addresses without any further DNS lookups.
func (s *Server) dialTarget(addrs []netip.Addr, port int) (net.Conn, error) {
	portStr := strconv.Itoa(port)
	var lastErr error
	for _, addr := range addrs {
		if s.config.ForceIPv4 && !addr.Is4() {
			continue
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr.String(), portStr), s.config.ConnectionTimeout)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no IPv4 address found")
}

// idleConn wraps a net.Conn and resets the deadline after every successful
// I/O operation, implementing a true idle timeout instead of an absolute one.
// Without this, SetDeadline(now+300s) kills any active stream older than 5
// minutes even when data is flowing continuously (e.g. video playback).
type idleConn struct {
	net.Conn
	idle time.Duration
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	c.SetDeadline(time.Now().Add(idle)) //nolint:errcheck // prime initial deadline
	return &idleConn{Conn: c, idle: idle}
}

func (c *idleConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.idle)) //nolint:errcheck
	}
	return n, err
}

func (c *idleConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.idle)) //nolint:errcheck
	}
	return n, err
}

// CloseWrite forwards a half-close to the wrapped connection when supported.
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// closeWrite signals EOF on dst without destroying it, so the reverse
// direction of a relay can keep flowing (proper TCP half-close semantics).
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	c.Close()
}

// relay bidirectionally relays data between two connections.
// Both sides are wrapped with idleConn so the deadline resets on every
// successful read/write — a long video stream is never killed mid-transfer.
// When one direction ends, only that direction is closed (half-close): a
// client FIN must not truncate response bytes still in flight.
func (s *Server) relay(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyData := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, BufferSize)
		_, _ = io.CopyBuffer(dst, src, buf)
		closeWrite(dst)
	}

	go copyData(conn1, conn2)
	go copyData(conn2, conn1)

	wg.Wait()
}

// Shadowsocks AEAD Cipher implementation
type ShadowsocksCipher struct {
	key    []byte
	cipher string
	replay *replayCache
}

func NewShadowsocksCipher(password, method string, replay *replayCache) (*ShadowsocksCipher, error) {
	var keySize int
	switch method {
	case "aes-128-gcm":
		keySize = 16
	case "aes-256-gcm":
		keySize = 32
	default:
		// Only ciphers actually implemented by newAEAD are accepted, so a
		// misconfiguration fails at startup instead of per-connection.
		return nil, fmt.Errorf("unsupported cipher: %s", method)
	}

	key := evpBytesToKey(password, keySize)
	return &ShadowsocksCipher{
		key:    key,
		cipher: method,
		replay: replay,
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

// HKDF-SHA1 key derivation for AEAD ciphers (stdlib crypto/hkdf, Go 1.24+)
func hkdfSHA1(secret, salt, info []byte, keyLen int) ([]byte, error) {
	return hkdf.Key(sha1.New, secret, salt, string(info), keyLen)
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

	// Reject replayed handshakes: a salt may only be used once.
	if sc.replay != nil && !sc.replay.checkOrAdd(salt) {
		return nil, errors.New("replayed Shadowsocks salt rejected")
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
	if payloadLen < 1 || payloadLen > 0x3FFF {
		return 0, fmt.Errorf("invalid payload length: %d", payloadLen)
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

// CloseWrite forwards a half-close past the AEAD wrapper when supported.
func (c *ShadowsocksConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// handleShadowsocks handles Shadowsocks protocol.
func (s *Server) handleShadowsocks(conn net.Conn) {
	clientIP := extractIP(conn.RemoteAddr())

	// Create cipher
	cipher, err := NewShadowsocksCipher(s.config.ShadowsocksKey, s.config.ShadowsocksCipher, s.replay)
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

	// Connect to target (same egress port policy as the other protocols)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if blockedTargetPorts[int(port)] {
		log.Printf("Blocked Shadowsocks egress port %d from %s to %s", port, clientIP, sanitizeLog(target))
		return
	}

	addrs, err := s.resolveTarget(host)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			log.Printf("Blocked unsafe Shadowsocks target from %s to %s", clientIP, sanitizeLog(target))
		} else {
			log.Printf("Shadowsocks: Failed to resolve %s from %s: %v", sanitizeLog(host), clientIP, err)
		}
		return
	}

	remote, err := s.dialTarget(addrs, int(port))
	if err != nil {
		log.Printf("Shadowsocks: Failed to connect to %s: %v", sanitizeLog(target), err)
		return
	}
	defer remote.Close()

	log.Printf("%s connected to %s via Shadowsocks", clientIP, sanitizeLog(target))

	s.relay(newIdleConn(ssConn, s.config.IdleTimeout), newIdleConn(remote, s.config.IdleTimeout))
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

// runHealthCheck probes the local proxy end to end: connect, authenticate
// with the configured credentials, and issue a CONNECT to a loopback target.
// The egress policy must reject it with 403 — anything else (or no answer)
// means the accept loop, protocol detection, or auth path is broken.
// Returns the process exit code.
func runHealthCheck(config *Config) int {
	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: dial failed: %v\n", err)
		return 1
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	creds := base64.StdEncoding.EncodeToString([]byte(config.Username + ":" + config.Password))
	req := fmt.Sprintf("CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nProxy-Authorization: Basic %s\r\n\r\n", creds)
	if _, err := conn.Write([]byte(req)); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: write failed: %v\n", err)
		return 1
	}

	line, err := bufio.NewReaderSize(conn, 256).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: no response: %v\n", err)
		return 1
	}
	if strings.HasPrefix(line, "HTTP/1.1 403") {
		fmt.Println("healthcheck: ok")
		return 0
	}
	fmt.Fprintf(os.Stderr, "healthcheck: unexpected response: %q\n", strings.TrimRight(line, "\r\n"))
	return 1
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	healthCheck := flag.Bool("healthcheck", false, "probe the local proxy listener and exit 0 (healthy) or 1 (unhealthy)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gost-proxy %s\n", appVersion)
		os.Exit(0)
	}

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
		SniffTimeout:      time.Duration(getEnvInt("GOST_SNIFF_TIMEOUT", 10, 1, 60)) * time.Second,
		ConnectionTimeout: time.Duration(getEnvInt("GOST_TIMEOUT", 15, 3, 300)) * time.Second,
		IdleTimeout:       time.Duration(getEnvInt("GOST_IDLE_TIMEOUT", 300, 5, 86400)) * time.Second,
		AuthFailLimit:     getEnvInt("GOST_AUTH_FAIL_LIMIT", 5, 1, 100),
		AuthFailWindow:    time.Duration(getEnvInt("GOST_AUTH_FAIL_WINDOW", 60, 1, 3600)) * time.Second,
		AllowNoAuth:       getEnvBool("GOST_ALLOW_NOAUTH", false),
		ForceIPv4:         getEnvBool("GOST_FORCE_IPV4", true),
	}

	if *healthCheck {
		os.Exit(runHealthCheck(config))
	}

	// Set default Shadowsocks cipher if key provided but cipher not specified
	if config.ShadowsocksKey != "" && config.ShadowsocksCipher == "" {
		config.ShadowsocksCipher = "aes-256-gcm"
	}

	// Validate required config
	if config.Username == "" || config.Password == "" {
		log.Fatal("GOST_USER and GOST_PASS must be set")
	}

	// Fail fast on an unimplemented Shadowsocks cipher instead of dropping
	// every connection at runtime.
	if config.ShadowsocksKey != "" {
		sc, err := NewShadowsocksCipher(config.ShadowsocksKey, config.ShadowsocksCipher, nil)
		if err != nil {
			log.Fatalf("Invalid GOST_SS_CIPHER: %v", err)
		}
		if _, err := sc.newAEAD(make([]byte, sc.getSaltSize())); err != nil {
			log.Fatalf("Invalid GOST_SS_CIPHER: %v", err)
		}
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
