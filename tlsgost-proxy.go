package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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
	ProtocolSOCKS5  = "socks5"
	ProtocolHTTP    = "http"
	ProtocolUnknown = "unknown"

	SOCKS5Version      = 0x05
	SOCKS5AuthNone     = 0x00
	SOCKS5AuthPassword = 0x02
	SOCKS5AuthNoMethod = 0xFF
	SOCKS5CmdConnect   = 0x01
	SOCKS5AtypIPv4     = 0x01
	SOCKS5AtypDomain   = 0x03
	SOCKS5AtypIPv6     = 0x04

	SOCKS5RepSuccess         = 0x00
	SOCKS5RepNotAllowed      = 0x02
	SOCKS5RepHostUnreachable = 0x04
	SOCKS5RepTTLExpired      = 0x06
	SOCKS5RepCmdNotSupported  = 0x07
	SOCKS5RepAtypNotSupported = 0x08

	BufferSize = 32 * 1024

	// appVersion is reported by -version.
	appVersion = "1.1.0"

	// maxHTTPHeaderBytes caps the request line + header block a client may
	// send before the connection is dropped (memory-DoS guard).
	maxHTTPHeaderBytes = 8 * 1024

	// maxAuthFailureEntries bounds the per-IP auth failure map.
	maxAuthFailureEntries = 10000
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

type Config struct {
	Host              string
	Port              int
	Username          string
	Password          string
	TLSCertFile       string
	TLSKeyFile        string
	TLSMinVersion     uint16
	SNI               string
	CertIPs           []net.IP
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

type Server struct {
	config        *Config
	listener      net.Listener
	tlsConfig     *tls.Config
	certPtr       atomic.Pointer[tls.Certificate]
	certExpiry    time.Time
	selfSigned    bool
	activeConns   int64
	connSemaphore chan struct{}
	authFailures  map[string][]time.Time
	authMutex     sync.RWMutex
	shutdown      chan struct{}
	wg            sync.WaitGroup
	running       atomic.Bool
}

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

// CloseWrite half-closes the underlying connection when it supports it (a
// *tls.Conn sends close_notify), so a finished relay direction can signal
// EOF without killing the other.
func (w *ConnectionWrapper) CloseWrite() error {
	if cw, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return w.Conn.Close()
}

func NewServer(config *Config) *Server {
	return &Server{
		config:        config,
		connSemaphore: make(chan struct{}, config.MaxConnections),
		authFailures:  make(map[string][]time.Time),
		shutdown:      make(chan struct{}),
	}
}

func (s *Server) buildTLSConfig() error {
	var cert tls.Certificate
	var expiry time.Time

	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		var err error
		cert, err = tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert/key: %w", err)
		}
		if len(cert.Certificate) > 0 {
			if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				expiry = parsed.NotAfter
			}
		}
		log.Printf("Loaded TLS certificate from %s", s.config.TLSCertFile)
	} else {
		var err error
		cert, expiry, err = generateSelfSignedCert(s.config.SNI, s.config.CertIPs)
		if err != nil {
			return fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
		s.selfSigned = true
		log.Println("Generated self-signed TLS certificate (set TLSGOST_TLS_CERT/TLSGOST_TLS_KEY for production)")
	}

	s.certPtr.Store(&cert)
	s.certExpiry = expiry

	tlsCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.certPtr.Load(), nil
		},
		MinVersion: s.config.TLSMinVersion,
		// The server speaks neither h2 nor HTTP/1.1 at the application layer;
		// advertising them keeps the TLS fingerprint plausible to observers.
		NextProtos: []string{"h2", "http/1.1"},
	}

	if s.config.TLSMinVersion == tls.VersionTLS12 {
		// TLS 1.2 requested via TLSGOST_TLS_MIN_VERSION: restrict to AEAD
		// cipher suites (the Go defaults include CBC).
		tlsCfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
		log.Println("WARNING: TLS minimum version set to 1.2; TLS 1.3 is recommended (TLSGOST_TLS_MIN_VERSION=1.3)")
	}

	if s.config.SNI != "" {
		tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName != s.config.SNI {
				return nil, fmt.Errorf("SNI mismatch: rejected %q", hello.ServerName)
			}
			return nil, nil
		}
	}

	s.tlsConfig = tlsCfg
	return nil
}

func generateSelfSignedCert(domain string, ips []net.IP) (tls.Certificate, time.Time, error) {
	if domain == "" {
		domain = "example.com"
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	notAfter := time.Now().Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
		IPAddresses:  ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}

	return cert, notAfter, nil
}

func (s *Server) Start() error {
	if err := s.buildTLSConfig(); err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind %s: %w", addr, err)
	}

	s.listener = tls.NewListener(tcpLn, s.tlsConfig)
	s.running.Store(true)

	log.Printf("TLS proxy listening on %s", addr)
	log.Printf("Max connections: %d", s.config.MaxConnections)

	noAuth := ""
	if s.config.AllowNoAuth {
		noAuth = " (no-auth allowed)"
	}
	log.Printf("Protocols: SOCKS5+TLS, HTTP CONNECT+TLS%s", noAuth)

	if s.config.SNI != "" {
		log.Printf("SNI filter: %s", s.config.SNI)
	}

	fingerprint := s.certFingerprint()
	if fingerprint != "" {
		log.Printf("Certificate SHA-256: %s", fingerprint)
	}

	if !s.certExpiry.IsZero() {
		log.Printf("Certificate expires: %s", s.certExpiry.Format("2006-01-02"))
		if s.selfSigned {
			log.Println("Auto-renewal enabled (will regenerate 30 days before expiry)")
		}
	}

	s.startCertRenewal()

	go s.handleSignals()

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

func (s *Server) certFingerprint() string {
	cert := s.certPtr.Load()
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	hash := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(hash[:])
}

func (s *Server) startCertRenewal() {
	if s.selfSigned {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-s.shutdown:
					return
				case <-ticker.C:
					remaining := time.Until(s.certExpiry)
					if remaining < 30*24*time.Hour {
						s.renewCert()
					} else {
						log.Printf("Certificate valid for %d more days", int(remaining.Hours()/24))
					}
				}
			}
		}()
		return
	}

	// User-provided certificates: watch the mounted files and hot-reload
	// when they change (certbot renewals, rotated k8s secrets). Note that
	// self-signed renewal rotates the key, so client fingerprint pinning
	// changes on rotation — that is intentional for generated certs.
	if s.config.TLSCertFile == "" {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		lastMod := certModTime(s.config.TLSCertFile, s.config.TLSKeyFile)

		for {
			select {
			case <-s.shutdown:
				return
			case <-ticker.C:
				mod := certModTime(s.config.TLSCertFile, s.config.TLSKeyFile)
				if mod.Equal(lastMod) {
					continue
				}
				lastMod = mod
				s.reloadCert()
			}
		}
	}()
}

func certModTime(files ...string) time.Time {
	var latest time.Time
	for _, f := range files {
		if f == "" {
			continue
		}
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
	}
	return latest
}

func (s *Server) reloadCert() {
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		log.Printf("Failed to reload TLS certificate: %v (keeping previous)", err)
		return
	}
	s.certPtr.Store(&cert)
	if len(cert.Certificate) > 0 {
		if parsed, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			s.certExpiry = parsed.NotAfter
		}
	}
	log.Printf("Reloaded TLS certificate from %s (expires %s)", s.config.TLSCertFile, s.certExpiry.Format("2006-01-02"))
	log.Printf("New certificate SHA-256: %s", s.certFingerprint())
}

func (s *Server) renewCert() {
	cert, expiry, err := generateSelfSignedCert(s.config.SNI, s.config.CertIPs)
	if err != nil {
		log.Printf("Failed to renew self-signed certificate: %v", err)
		return
	}
	s.certPtr.Store(&cert)
	s.certExpiry = expiry
	log.Printf("Renewed self-signed TLS certificate (expires %s)", expiry.Format("2006-01-02"))
	log.Printf("New certificate SHA-256: %s", s.certFingerprint())
}

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

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All connections closed gracefully")
	case <-time.After(30 * time.Second):
		active := atomic.LoadInt64(&s.activeConns)
		log.Printf("Force shutdown with %d active connections", active)
	}

	os.Exit(0)
}

func (s *Server) handleConnection(rawConn net.Conn) {
	defer func() {
		rawConn.Close()
		<-s.connSemaphore
		atomic.AddInt64(&s.activeConns, -1)
		s.wg.Done()
	}()

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		return
	}

	tlsConn.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return
		}
		log.Printf("TLS handshake failed from %s: %v", rawConn.RemoteAddr(), err)
		return
	}
	tlsConn.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	proto := "unknown"
	switch state.Version {
	case tls.VersionTLS12:
		proto = "TLS 1.2"
	case tls.VersionTLS13:
		proto = "TLS 1.3"
	}

	conn := NewConnectionWrapper(tlsConn)

	// Protocol detection runs after the TLS handshake but before auth, so it
	// uses the shorter sniff timeout: an unauthenticated client cannot hold
	// a connection slot for the full handshake window by dribbling bytes.
	rawConn.SetReadDeadline(time.Now().Add(s.config.SniffTimeout))
	protocol, err := s.detectProtocol(conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("Protocol detection timeout from %s (%s)", conn.RemoteAddr(), proto)
			return
		}
		log.Printf("Protocol detection failed from %s (%s): %v", conn.RemoteAddr(), proto, err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(s.config.ConnectionTimeout))

	switch protocol {
	case ProtocolSOCKS5:
		s.handleSOCKS5(conn)
	case ProtocolHTTP:
		s.handleHTTP(conn)
	default:
		log.Printf("Unknown protocol from %s (%s)", conn.RemoteAddr(), proto)
	}
}

func (s *Server) detectProtocol(conn *ConnectionWrapper) (string, error) {
	first, err := conn.Peek(1)
	if err != nil {
		return ProtocolUnknown, err
	}
	if len(first) > 0 && first[0] == SOCKS5Version {
		return ProtocolSOCKS5, nil
	}

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

	return ProtocolUnknown, nil
}

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

func (s *Server) handleSOCKS5(conn *ConnectionWrapper) {
	clientIP := extractIP(conn.RemoteAddr())

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}

	if greeting[0] != SOCKS5Version {
		return
	}

	nmethods := greeting[1]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

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

	if _, err := conn.Write([]byte{SOCKS5Version, selectedMethod}); err != nil {
		return
	}

	if selectedMethod == SOCKS5AuthNoMethod {
		log.Printf("No compatible auth method from %s", clientIP)
		return
	}

	if selectedMethod == SOCKS5AuthPassword {
		if !s.authenticateSOCKS5(conn, clientIP) {
			return
		}
	} else {
		log.Printf("Accepted no-auth SOCKS5+TLS from %s", clientIP)
	}

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

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// Egress port policy applies on every protocol (HTTP CONNECT included),
	// so the proxy cannot be abused e.g. for SMTP spam relay over SOCKS5.
	if blockedTargetPorts[int(port)] {
		log.Printf("Blocked SOCKS5+TLS egress port %d from %s to %s", port, clientIP, sanitizeLog(target))
		s.sendSOCKS5Reply(conn, SOCKS5RepNotAllowed)
		return
	}

	// Resolve and validate once, then dial the validated IP literally —
	// re-resolving here would open a DNS-rebinding TOCTOU window.
	addrs, err := s.resolveTarget(host)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			log.Printf("Blocked unsafe SOCKS5+TLS target from %s to %s", clientIP, sanitizeLog(target))
			s.sendSOCKS5Reply(conn, SOCKS5RepNotAllowed)
		} else {
			log.Printf("Failed to resolve SOCKS5+TLS target %s from %s: %v", sanitizeLog(host), clientIP, err)
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

	bindAddr, _ := remote.LocalAddr().(*net.TCPAddr)
	if bindAddr == nil {
		bindAddr = &net.TCPAddr{}
	}
	reply := s.buildSOCKS5Reply(SOCKS5RepSuccess, bindAddr)
	if _, err := conn.Write(reply); err != nil {
		return
	}

	log.Printf("%s connected to %s via SOCKS5+TLS", clientIP, sanitizeLog(target))
	s.relay(newIdleConn(conn, s.config.IdleTimeout), newIdleConn(remote, s.config.IdleTimeout))
}

func (s *Server) authenticateSOCKS5(conn *ConnectionWrapper, clientIP string) bool {
	if !s.checkRateLimit(clientIP) {
		conn.Write([]byte{0x01, 0x01})
		return false
	}

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

	username := make([]byte, userLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return false
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return false
	}

	password := make([]byte, passLenBuf[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return false
	}

	userMatch := subtle.ConstantTimeCompare(username, []byte(s.config.Username)) == 1
	passMatch := subtle.ConstantTimeCompare(password, []byte(s.config.Password)) == 1

	if !userMatch || !passMatch {
		s.recordAuthFailure(clientIP)
		conn.Write([]byte{0x01, 0x01})
		log.Printf("SOCKS5+TLS auth failed from %s", clientIP)
		return false
	}

	conn.Write([]byte{0x01, 0x00})
	return true
}

func (s *Server) sendSOCKS5Reply(conn net.Conn, rep byte) {
	reply := []byte{SOCKS5Version, rep, 0x00, SOCKS5AtypIPv4, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)
}

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

func (s *Server) handleHTTP(conn *ConnectionWrapper) {
	clientIP := extractIP(conn.RemoteAddr())

	// Read the request line and headers directly from the wrapper's buffered
	// reader under a hard byte cap: stops multi-GB header flooding while
	// preserving bytes pipelined after the headers for the tunnel.
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

	if method != "CONNECT" {
		s.sendHTTPError(conn, 405, "Method Not Allowed")
		return
	}

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

	if !s.authenticateHTTP(headers, clientIP) {
		s.sendHTTPAuthRequired(conn)
		return
	}

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

	if blockedTargetPorts[port] {
		s.sendHTTPError(conn, 403, "Port Not Allowed")
		return
	}

	// Resolve and validate once, then dial the validated IP literally.
	addrs, err := s.resolveTarget(host)
	if err != nil {
		if errors.Is(err, errBlockedTarget) {
			log.Printf("Blocked unsafe HTTP+TLS target from %s to %s", clientIP, sanitizeLog(target))
			s.sendHTTPError(conn, 403, "Target Not Allowed")
		} else {
			log.Printf("Failed to resolve HTTP+TLS target %s from %s: %v", sanitizeLog(host), clientIP, err)
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

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	log.Printf("%s connected to %s via HTTP+TLS", clientIP, sanitizeLog(targetAddr))

	s.relay(newIdleConn(conn, s.config.IdleTimeout), newIdleConn(remote, s.config.IdleTimeout))
}

func (s *Server) authenticateHTTP(headers map[string]string, clientIP string) bool {
	if !s.checkRateLimit(clientIP) {
		return false
	}

	authHeader := headers["proxy-authorization"]
	if authHeader == "" {
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "basic" {
		s.recordAuthFailure(clientIP)
		return false
	}

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

	userMatch := subtle.ConstantTimeCompare([]byte(credentials[0]), []byte(s.config.Username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(credentials[1]), []byte(s.config.Password)) == 1

	if !userMatch || !passMatch {
		s.recordAuthFailure(clientIP)
		log.Printf("HTTP+TLS auth failed from %s", clientIP)
		return false
	}

	return true
}

func (s *Server) sendHTTPError(conn net.Conn, code int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, message)
	conn.Write([]byte(response))
}

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

type idleConn struct {
	net.Conn
	idle time.Duration
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	c.SetDeadline(time.Now().Add(idle)) //nolint:errcheck
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

func (s *Server) relay(conn1, conn2 net.Conn) {
	// Half-close semantics: when one direction ends, only that direction is
	// closed — a client FIN must not truncate response bytes in flight.
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

func getEnvBool(name string, defaultVal bool) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if val == "" {
		return defaultVal
	}
	return val == "1" || val == "true" || val == "yes" || val == "on"
}

func parseTLSMinVersion(v string) uint16 {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "1.2", "tls12", "tls1.2":
		return tls.VersionTLS12
	default:
		return tls.VersionTLS13
	}
}

// runHealthCheck probes the local proxy end to end: complete a TLS handshake
// against the live listener, authenticate with the configured credentials,
// and issue a CONNECT to a loopback target. The egress policy must reject it
// with 403 — anything else (or no answer) means the TLS stack, accept loop,
// protocol detection, or auth path is broken. Returns the process exit code.
func runHealthCheck(config *Config) int {
	addr := fmt.Sprintf("127.0.0.1:%d", config.Port)

	serverName := config.SNI
	if serverName == "" {
		serverName = "localhost"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		// This is a liveness probe against the local listener, not a trust
		// decision; the cert may be self-signed, so verification is off.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: TLS handshake failed: %v\n", err)
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
	healthCheck := flag.Bool("healthcheck", false, "probe the local proxy over TLS and exit 0 (healthy) or 1 (unhealthy)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("tlsgost-proxy %s\n", appVersion)
		os.Exit(0)
	}

	config := &Config{
		Host:              os.Getenv("TLSGOST_HOST"),
		Port:              getEnvInt("TLSGOST_PORT", 8443, 1, 65535),
		Username:          os.Getenv("TLSGOST_USER"),
		Password:          os.Getenv("TLSGOST_PASS"),
		TLSCertFile:       os.Getenv("TLSGOST_TLS_CERT"),
		TLSKeyFile:        os.Getenv("TLSGOST_TLS_KEY"),
		TLSMinVersion:     parseTLSMinVersion(os.Getenv("TLSGOST_TLS_MIN_VERSION")),
		SNI:               os.Getenv("TLSGOST_SNI"),
		MaxConnections:    getEnvInt("TLSGOST_MAX_CONN", 200, 1, 10000),
		HandshakeTimeout:  time.Duration(getEnvInt("TLSGOST_HANDSHAKE_TIMEOUT", 30, 5, 300)) * time.Second,
		SniffTimeout:      time.Duration(getEnvInt("TLSGOST_SNIFF_TIMEOUT", 10, 1, 60)) * time.Second,
		ConnectionTimeout: time.Duration(getEnvInt("TLSGOST_TIMEOUT", 15, 3, 300)) * time.Second,
		IdleTimeout:       time.Duration(getEnvInt("TLSGOST_IDLE_TIMEOUT", 300, 5, 86400)) * time.Second,
		AuthFailLimit:     getEnvInt("TLSGOST_AUTH_FAIL_LIMIT", 5, 1, 100),
		AuthFailWindow:    time.Duration(getEnvInt("TLSGOST_AUTH_FAIL_WINDOW", 60, 1, 3600)) * time.Second,
		AllowNoAuth:       getEnvBool("TLSGOST_ALLOW_NOAUTH", false),
		ForceIPv4:         getEnvBool("TLSGOST_FORCE_IPV4", true),
	}

	// Optional IP SANs for the self-signed certificate (clients connecting
	// by raw IP need one to verify the cert).
	for _, s := range strings.Split(os.Getenv("TLSGOST_CERT_IPS"), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			log.Fatalf("TLSGOST_CERT_IPS: invalid IP %q", s)
		}
		config.CertIPs = append(config.CertIPs, net.IP(ip.AsSlice()))
	}

	if *healthCheck {
		os.Exit(runHealthCheck(config))
	}

	if config.Username == "" || config.Password == "" {
		log.Fatal("TLSGOST_USER and TLSGOST_PASS must be set")
	}

	if config.Host == "" {
		config.Host = "0.0.0.0"
	}

	server := NewServer(config)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
