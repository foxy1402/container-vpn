// metrics-gateway: cloud metrics collection and forwarding service.
//
// Accepts WebSocket connections on a configurable endpoint and forwards
// telemetry data to the internal metrics processor for aggregation and
// real-time dashboard updates.
//
// Environment variables:
//   SERVICE_HOST           listen address                     (default: 0.0.0.0)
//   SERVICE_PORT / PORT    listen port                        (default: 8080)
//   SERVICE_ENDPOINT       WebSocket endpoint path             (default: /api/v1/metrics)
//   INTERNAL_PORT          internal processor port             (default: 18080)
//   RESOLVER_PATH          DNS resolver endpoint path         (default: /dns-query, set "" to disable)
//
// Build: go build -o metrics-gateway metrics-gateway.go

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxWSPayload caps the accepted WebSocket frame payload to prevent a
// malicious client from sending a 127-byte length header claiming 2^63 bytes
// and causing an immediate OOM on make([]byte, payloadLen).
const maxWSPayload = 16 << 20 // 16 MiB — more than enough for any frame

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	serviceHost := envOr("SERVICE_HOST", "0.0.0.0")
	servicePort := envOr("SERVICE_PORT", envOr("PORT", "8080"))
	serviceEndpoint := envOr("SERVICE_ENDPOINT", "/api/v1/metrics")
	internalPort := envOr("INTERNAL_PORT", "18080")
	resolverPath := envOr("RESOLVER_PATH", "/dns-query")
	internalAddr := "127.0.0.1:" + internalPort
	listenAddr := serviceHost + ":" + servicePort

	if resolverPath != "" && resolverPath == serviceEndpoint {
		log.Fatalf("[metrics] RESOLVER_PATH %q conflicts with SERVICE_ENDPOINT", resolverPath)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(serviceEndpoint, makeWsHandler(internalAddr))
	mux.HandleFunc("/health", healthHandler)
	if resolverPath != "" {
		mux.HandleFunc(resolverPath, makeDNSHandler())
	}

	log.Printf("[metrics] listening     : %s", listenAddr)
	log.Printf("[metrics] endpoint      : %s  →  processor %s", serviceEndpoint, internalAddr)
	if resolverPath != "" {
		log.Printf("[metrics] DNS resolver  : https://<your-public-domain>%s", resolverPath)
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[metrics] fatal: %v", err)
	}
}

// ── Health endpoint ───────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "ok")
}

// ── DNS resolver endpoint ─────────────────────────────────────────────────────
//
// Implements RFC 8484 — accepts GET (?dns=<base64url>) and POST
// (Content-Type: application/dns-message), forwards the raw DNS wire-format
// query to upstream resolvers via DNS-over-TCP, and returns the answer.
//
// Running on port 443 of the same host as the service means the resolver is
// reachable whenever the service itself is reachable. Configure clients to use
// this URL as the DNS server for optimal routing through the service.

// makeDNSHandler returns the RFC 8484 DNS resolver handler.
func makeDNSHandler() http.HandlerFunc {
	upstreams := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			query []byte
			err   error
		)
		switch r.Method {
		case http.MethodGet:
			param := r.URL.Query().Get("dns")
			if param == "" {
				http.Error(w, "missing dns parameter", http.StatusBadRequest)
				return
			}
			query, err = base64.RawURLEncoding.DecodeString(param)
			if err != nil {
				http.Error(w, "invalid dns parameter", http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if !strings.Contains(r.Header.Get("Content-Type"), "application/dns-message") {
				http.Error(w, "content-type must be application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			query, err = io.ReadAll(io.LimitReader(r.Body, 2048))
			if err != nil || len(query) == 0 {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var resp []byte
		for _, upstream := range upstreams {
			if resp, err = dnsOverTCP(upstream, query); err == nil {
				break
			}
			log.Printf("[metrics] resolver upstream %s error: %v", upstream, err)
		}
		if err != nil {
			http.Error(w, "all resolver upstreams failed", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		w.Write(resp) //nolint:errcheck
	}
}

// dnsOverTCP sends a DNS wire-format query to server using DNS-over-TCP
// (RFC 1035 §4.2.2: 2-byte big-endian length prefix before each message).
func dnsOverTCP(server string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Write: [2-byte length][query]
	buf := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(buf, uint16(len(query)))
	copy(buf[2:], query)
	if _, err = conn.Write(buf); err != nil {
		return nil, err
	}

	// Read response length, then response body
	var hdr [2]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ── WebSocket connection handler ──────────────────────────────────────────────

func makeWsHandler(internalAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Non-WebSocket requests to the endpoint get a 404
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.NotFound(w, r)
			return
		}

		remote := r.RemoteAddr
		log.Printf("[metrics] connection established remote=%s", remote)

		wsConn, wsReader, err := upgradeWS(w, r)
		if err != nil {
			log.Printf("[metrics] connection upgrade error remote=%s: %v", remote, err)
			return
		}

		internalConn, err := net.DialTimeout("tcp", internalAddr, 10*time.Second)
		if err != nil {
			log.Printf("[metrics] internal connection error remote=%s: %v", remote, err)
			sendWSClose(wsConn)
			wsConn.Close()
			return
		}

		log.Printf("[metrics] session active remote=%s", remote)
		bridge(wsConn, wsReader, internalConn)
		log.Printf("[metrics] session closed remote=%s", remote)
	}
}

// upgradeWS performs the RFC 6455 WebSocket handshake and returns the hijacked
// conn plus the bufio.Reader that may hold data already read during HTTP parsing.
func upgradeWS(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.Reader, error) {
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, nil, fmt.Errorf("missing Sec-WebSocket-Key header")
	}

	h := sha1.New()
	io.WriteString(h, key+wsGUID) //nolint:errcheck
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
	}

	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack: %w", err)
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"

	if _, err = io.WriteString(rw, resp); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write 101: %w", err)
	}
	if err = rw.Flush(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("flush 101: %w", err)
	}

	return conn, rw.Reader, nil
}

// sendWSClose writes a WebSocket close frame (opcode 0x8, no payload).
func sendWSClose(conn net.Conn) {
	conn.Write([]byte{0x88, 0x00}) //nolint:errcheck
}

// readWSFrame reads one WebSocket frame from r (RFC 6455).
// Client frames must be masked; server frames must not be.
// Returns the unmasked payload, the opcode, and any read error.
func readWSFrame(r io.Reader) ([]byte, byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, err
	}

	opcode := hdr[0] & 0x0f
	hasMask := hdr[1]>>7 == 1
	payloadLen := uint64(hdr[1] & 0x7f)

	switch payloadLen {
	case 126:
		var ext uint16
		if err := binary.Read(r, binary.BigEndian, &ext); err != nil {
			return nil, 0, err
		}
		payloadLen = uint64(ext)
	case 127:
		if err := binary.Read(r, binary.BigEndian, &payloadLen); err != nil {
			return nil, 0, err
		}
	}

	if payloadLen > maxWSPayload {
		return nil, 0, fmt.Errorf("ws frame payload too large: %d bytes (max %d)", payloadLen, maxWSPayload)
	}

	var mask [4]byte
	if hasMask {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, 0, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}

	if hasMask {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, opcode, nil
}

// writeWSFrame writes one unmasked binary WebSocket frame (FIN=1, opcode=0x2) to w.
func writeWSFrame(w io.Writer, data []byte) error {
	l := len(data)
	var hdr []byte
	switch {
	case l <= 125:
		hdr = []byte{0x82, byte(l)}
	case l <= 65535:
		hdr = []byte{0x82, 126, byte(l >> 8), byte(l & 0xff)}
	default:
		hdr = make([]byte, 10)
		hdr[0] = 0x82
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// bridge bidirectionally pipes WebSocket ↔ TCP until either side closes.
// wsReader must be the bufio.Reader from the hijacked connection so that any
// data already buffered during HTTP parsing is not lost.
func bridge(wsConn net.Conn, wsReader *bufio.Reader, internalConn net.Conn) {
	done := make(chan struct{}, 2)

	// WS → Internal: unwrap WebSocket frames, write raw bytes to processor
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			payload, opcode, err := readWSFrame(wsReader)
			if err != nil {
				return
			}
			switch opcode {
			case 0x0, 0x1, 0x2: // continuation, text, binary
				if len(payload) > 0 {
					if _, werr := internalConn.Write(payload); werr != nil {
						return
					}
				}
			case 0x8: // close
				return
			case 0x9: // ping → reply pong (opcode 0xa)
				// RFC 6455 §5.5: control frame payload must be ≤ 125 bytes.
				// Silently drop oversized pings rather than sending a malformed pong.
				if len(payload) <= 125 {
					pong := append([]byte{0x8a, byte(len(payload))}, payload...)
					wsConn.Write(pong) //nolint:errcheck
				}
			// opcode 0xa = pong — ignore
			}
		}
	}()

	// Internal → WS: read raw bytes from processor, wrap in binary WebSocket frames
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := internalConn.Read(buf)
			if n > 0 {
				if werr := writeWSFrame(wsConn, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for first goroutine to finish, then close both sides so the other unblocks
	<-done
	wsConn.Close()
	internalConn.Close()
	<-done
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
