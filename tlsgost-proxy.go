package main

import (
	"bufio"
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
)

type Config struct {
	Host              string
	Port              int
	Username          string
	Password          string
	TLSCertFile       string
	TLSKeyFile        string
	TLSMinVersion     uint16
	SNI               string
	MaxConnections    int
	HandshakeTimeout  time.Duration
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
		cert, expiry, err = generateSelfSignedCert()
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

func generateSelfSignedCert() (tls.Certificate, time.Time, error) {
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
		Subject:      pkix.Name{Organization: []string{"TLSGost Proxy"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.Printf("Accept error: %v", err)
				continue
			}
			break
		}

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
	if !s.selfSigned {
		return
	}
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
}

func (s *Server) renewCert() {
	cert, expiry, err := generateSelfSignedCert()
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

	rawConn.SetReadDeadline(time.Now().Add(s.config.HandshakeTimeout))
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

func (s *Server) recordAuthFailure(ip string) {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()
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
	if !s.isSafeTarget(host) {
		log.Printf("Blocked unsafe SOCKS5+TLS target from %s to %s", clientIP, target)
		s.sendSOCKS5Reply(conn, SOCKS5RepNotAllowed)
		return
	}

	var remote net.Conn
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

	bindAddr := remote.LocalAddr().(*net.TCPAddr)
	reply := s.buildSOCKS5Reply(SOCKS5RepSuccess, bindAddr)
	if _, err := conn.Write(reply); err != nil {
		return
	}

	log.Printf("%s connected to %s via SOCKS5+TLS", clientIP, target)
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

	requestLine, err := conn.reader.ReadString('\n')
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
		line, err := conn.reader.ReadString('\n')
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

	blockedPorts := map[int]bool{22: true, 23: true, 25: true, 3306: true, 5432: true, 6379: true, 27017: true}
	if blockedPorts[port] {
		s.sendHTTPError(conn, 403, "Port Not Allowed")
		return
	}
	if !s.isSafeTarget(host) {
		s.sendHTTPError(conn, 403, "Target Not Allowed")
		return
	}

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

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	log.Printf("%s connected to %s via HTTP+TLS", clientIP, targetAddr)

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

func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
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

func (s *Server) relay(conn1, conn2 net.Conn) {
	done := make(chan error, 2)

	copyData := func(dst, src net.Conn) {
		buf := make([]byte, BufferSize)
		_, err := io.CopyBuffer(dst, src, buf)
		done <- err
	}

	go copyData(conn1, conn2)
	go copyData(conn2, conn1)

	<-done

	conn1.Close()
	conn2.Close()

	<-done
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
	case "1.3", "tls13", "tls1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

func main() {
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
		ConnectionTimeout: time.Duration(getEnvInt("TLSGOST_TIMEOUT", 15, 3, 300)) * time.Second,
		IdleTimeout:       time.Duration(getEnvInt("TLSGOST_IDLE_TIMEOUT", 300, 5, 86400)) * time.Second,
		AuthFailLimit:     getEnvInt("TLSGOST_AUTH_FAIL_LIMIT", 5, 1, 100),
		AuthFailWindow:    time.Duration(getEnvInt("TLSGOST_AUTH_FAIL_WINDOW", 60, 1, 3600)) * time.Second,
		AllowNoAuth:       getEnvBool("TLSGOST_ALLOW_NOAUTH", false),
		ForceIPv4:         getEnvBool("TLSGOST_FORCE_IPV4", true),
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
