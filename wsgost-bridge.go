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
//   ADMIN_PATH             admin dashboard path                (default: /admin)
//   ADMIN_TOKEN            admin dashboard access token        (default: derived from AUTH_SECRET)
//   PUBLIC_HOST            public hostname in share links     (default: auto from Host header)
//   PUBLIC_PORT            public port in share links         (default: 443)
//   PUBLIC_TLS             include TLS in share links         (default: true)
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
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxWSPayload caps the accepted WebSocket frame payload to prevent a
// malicious client from sending a 127-byte length header claiming 2^63 bytes
// and causing an immediate OOM on make([]byte, payloadLen).
const maxWSPayload = 16 << 20 // 16 MiB — more than enough for any frame

// ── Config portal ─────────────────────────────────────────────────────────────

type portalData struct {
	SSURI        string // full ss:// share link (empty when SS_KEY not set)
	HasSS        bool
	PortalURL    string // full bookmarkable URL of this page (auto-built from request)
	DoHURL       string // full DNS-over-HTTPS URL (empty when WS_DNS_PATH is unset)
	ExtDoHURL    string // recommended external DoH for v2raytun Remote DNS field
	ExtHost      string
	ExtPort      string
	ExtTLS       bool
	Cipher       string
	SSKey        string
	WSPath       string
	AuthUser     string
	AuthSecret   string
}

var portalTmpl = template.Must(template.New("portal").Parse(portalHTML))

// portalHTML is the config page template.
// Passwords in data-val attrs are HTML-escaped by html/template;
// JS reads them via dataset.val which decodes entities back to raw chars.
const portalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Service Configuration</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:20px 14px}
.card{max-width:600px;margin:0 auto;background:#1e293b;border-radius:14px;padding:26px;box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{font-size:1.15rem;font-weight:700;color:#f8fafc;margin-bottom:3px}
.sub{font-size:.8rem;color:#64748b;margin-bottom:22px}
.sec{margin-bottom:22px}
.sec-title{font-size:.68rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#475569;margin-bottom:10px}
#qr{display:flex;justify-content:center;margin-bottom:12px;min-height:268px;align-items:center}
#qr canvas,#qr img{border-radius:8px;border:6px solid #fff}
.uribox{background:#020617;border:1px solid #1e3a5f;border-radius:8px;padding:10px 12px;font-family:monospace;font-size:.76rem;word-break:break-all;color:#38bdf8;margin-bottom:8px;cursor:pointer;user-select:all}
.uribox:active{color:#7dd3fc}
.row{display:flex;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.btn{background:#0284c7;color:#fff;border:none;border-radius:6px;padding:8px 18px;font-size:.82rem;cursor:pointer;font-weight:600}
.btn:active{background:#0369a1}
.btn-xs{padding:3px 9px;font-size:.7rem;background:#334155;border:none;border-radius:4px;color:#94a3b8;cursor:pointer;margin-left:6px;vertical-align:middle}
.btn-xs:active{background:#475569}
table{width:100%;border-collapse:collapse}
td{padding:8px 10px;border-bottom:1px solid #0f172a;font-size:.8rem;vertical-align:middle}
td:first-child{color:#64748b;width:42%;white-space:nowrap}
td.v{color:#f1f5f9;font-family:monospace;word-break:break-all}
.tag{display:inline-block;border-radius:4px;padding:2px 8px;font-size:.68rem;font-weight:700}
.t-blue{background:#0284c7;color:#fff}
.t-green{background:#059669;color:#fff}
.t-gray{background:#334155;color:#94a3b8}
.t-orange{background:#c2410c;color:#fff}
.note{background:#0c1628;border-left:3px solid #0284c7;border-radius:4px;padding:12px 14px;font-size:.78rem;color:#94a3b8;line-height:1.75}
.note b{color:#cbd5e1}
.note code{background:#1e293b;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.85em}
.warn{background:#1c0a00;border-left:3px solid #c2410c;border-radius:4px;padding:12px 14px;font-size:.78rem;color:#fdba74;line-height:1.75}
.warn b{color:#fb923c}
.warn code{background:#2c1100;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.85em}
.steps{list-style:none;counter-reset:step}
.steps li{counter-increment:step;padding:6px 0 6px 28px;position:relative;font-size:.78rem;color:#94a3b8;line-height:1.65}
.steps li::before{content:counter(step);position:absolute;left:0;top:7px;background:#0284c7;color:#fff;width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.65rem;font-weight:700}
.steps b{color:#cbd5e1}
.steps code{background:#1e293b;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.85em;color:#38bdf8}
</style>
</head>
<body>
<div class="card">
  <h1>Service Configuration</h1>
  <p class="sub">Scan the QR code or copy the share link directly into your client app.</p>

  <div class="sec">
    <div class="sec-title">This page — bookmark or copy the URL</div>
    <div class="uribox" id="portal-url" title="Click to copy" onclick="cpEl(this)">{{.PortalURL}}</div>
    <div class="row"><button class="btn" onclick="cpEl(document.getElementById('portal-url'),this)">Copy URL</button></div>
  </div>

{{if .HasSS}}
  <div class="sec">
    <div class="sec-title">Quick Import — Compatible Clients</div>
    <div id="qr"><span style="color:#475569;font-size:.82rem">Loading QR…</span></div>
    <div class="uribox" id="ss-uri" title="Click to copy" onclick="cpEl(this)">{{.SSURI}}</div>
    <div class="row">
      <button class="btn" onclick="cpEl(document.getElementById('ss-uri'),this)">Copy Link</button>
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">Connection Settings — Manual Configuration</div>
    <table>
      <tr><td>Server</td><td class="v">{{.ExtHost}}</td></tr>
      <tr><td>Port</td><td class="v">{{.ExtPort}}</td></tr>
      <tr><td>Method / Cipher</td><td class="v">{{.Cipher}}</td></tr>
      <tr><td>Password</td><td class="v">{{.SSKey}}<button class="btn-xs" data-val="{{.SSKey}}" onclick="cpData(this)">copy</button></td></tr>
      <tr><td>Transport</td><td class="v"><span class="tag t-blue">WebSocket</span></td></tr>
      <tr><td>Path</td><td class="v">{{.WSPath}}</td></tr>
      <tr><td>TLS / Security</td><td class="v">{{if .ExtTLS}}<span class="tag t-green">ON</span>{{else}}<span class="tag t-gray">OFF</span>{{end}}</td></tr>
    </table>
  </div>
{{else}}
  <div class="sec">
    <div class="note"><b>Primary configuration not enabled.</b><br>Set the <code>SS_KEY</code> env var to enable the primary configuration and generate a scannable QR code. Alternative authentication methods still work over WebSocket.</div>
  </div>
{{end}}

{{if and .AuthUser .AuthSecret}}
  <div class="sec">
    <div class="sec-title">Alternative Credentials — Advanced Clients</div>
    <table>
      <tr><td>Server</td><td class="v">{{.ExtHost}}</td></tr>
      <tr><td>Port</td><td class="v">{{.ExtPort}}</td></tr>
      <tr><td>Username</td><td class="v">{{.AuthUser}}<button class="btn-xs" data-val="{{.AuthUser}}" onclick="cpData(this)">copy</button></td></tr>
      <tr><td>Password</td><td class="v">{{.AuthSecret}}<button class="btn-xs" data-val="{{.AuthSecret}}" onclick="cpData(this)">copy</button></td></tr>
      <tr><td>Transport</td><td class="v"><span class="tag t-blue">WebSocket</span></td></tr>
      <tr><td>Path</td><td class="v">{{.WSPath}}</td></tr>
      <tr><td>TLS</td><td class="v">{{if .ExtTLS}}<span class="tag t-green">ON</span>{{else}}<span class="tag t-gray">OFF</span>{{end}}</td></tr>
    </table>
  </div>
{{end}}

  <!-- ── DNS FIX SECTION ─────────────────────────────────────────────────── -->
  <div class="sec">
    <div class="sec-title">⚠ Fix DNS leaks — required for browsers &amp; all apps</div>
    <div class="warn">
      <b>Why you see DNS_PROBE_POSSIBLE in Chrome / can't load Google:</b><br>
      The client uses a TUN virtual interface. Apps send raw DNS (UDP port 53) through it.
      By default the service resolves these using your ISP's DNS — <b>outside</b> the connection.
      The fix is to make the client send domain names <em>as-is</em> through the connection
      (server-side resolution) and use a reliable DoH server for the connection's own lookups.
    </div>
  </div>

  <div class="sec">
    <div class="sec-title">Fix step 1 — Client DNS settings (tap Settings gear → DNS)</div>
    <div class="note">
      <b>In your client → Settings (⚙) → DNS:</b>
    </div>
    <ul class="steps">
      <li>Open your client → tap the <b>⚙ gear icon</b> (top right) → tap <b>DNS</b></li>
      <li>Find <b>Remote DNS</b> field → clear it → paste:<br>
        <div style="margin-top:6px">
          <div class="uribox" id="ext-doh" onclick="cpEl(this)">{{.ExtDoHURL}}</div>
          <button class="btn" style="margin-top:4px" onclick="cpEl(document.getElementById('ext-doh'),this)">Copy</button>
        </div>
      </li>
      <li>Find <b>Domestic DNS</b> field (if shown) → set to <code>https://1.1.1.1/dns-query</code></li>
      <li>Set <b>Domain Strategy</b> to <code>UseIPv4</code> (or <em>IPIfNonMatch</em> if available)</li>
      <li>Tap <b>Save / Apply</b> then reconnect</li>
    </ul>
  </div>

{{if .DoHURL}}
  <div class="sec">
    <div class="sec-title">Fix step 2 (optional) — use this service's own DNS resolver</div>
    <div class="note">
      This server also runs a built-in DNS resolver endpoint. You can use it instead of Cloudflare/Google
      so <em>all</em> DNS resolves through the same server network.<br><br>
      <b>⚠ Important:</b> If you use this URL as your Remote DNS in the client, set its
      <em>detour/outbound to <b>direct</b></em> — the DNS resolver is on the same host as the service,
      so routing it <em>through</em> the service would be circular.
    </div>
    <div class="uribox" id="doh-url" title="Click to copy" onclick="cpEl(this)">{{.DoHURL}}</div>
    <div class="row"><button class="btn" onclick="cpEl(document.getElementById('doh-url'),this)">Copy DoH URL</button></div>
  </div>
{{end}}

  <div class="sec">
    <div class="sec-title">Fix step 3 — re-import the QR after DNS fix</div>
    <div class="note">
      The share link above already includes <code>domain_strategy=remote</code>. This tells
      the client to send domain names <b>as-is</b> to the server for resolution — no local
      pre-resolution happens. If you already have the server imported, delete it and re-scan
      the QR / re-paste the link above to pick up this flag.
    </div>
  </div>
  <!-- ── END DNS FIX SECTION ────────────────────────────────────────────── -->

  <div class="sec">
    <div class="note">
      <b>Compatible Client 1:</b> Add server → select encryption method → enter values above → tap <em>More options</em> → Network: <b>ws</b> → Path: <code>{{.WSPath}}</code> → save.<br><br>
      <b>Compatible Client 2 (iOS):</b> Tap + → select encryption method → fill values → Obfs: <b>websocket</b> → Obfs Param: <code>{{.WSPath}}</code>.<br><br>
      <b>Modern Clients:</b> Scan QR or paste the share link above; the app will auto-detect the configuration.
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
<script>
(function(){
  var uEl=document.getElementById('ss-uri');
  if(!uEl)return;
  var qEl=document.getElementById('qr');
  var uri=uEl.textContent.trim();
  function drawQR(){
    qEl.innerHTML='';
    new QRCode(qEl,{text:uri,width:260,height:260,colorDark:'#000000',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.M});
  }
  if(typeof QRCode!=='undefined'){drawQR();}
  else{
    var s=document.querySelector('script[src*="qrcodejs"]');
    if(s){s.addEventListener('load',drawQR);}
    qEl.innerHTML='<img src="https://api.qrserver.com/v1/create-qr-code/?size=260x260&data='+encodeURIComponent(uri)+'" alt="QR" style="border-radius:8px;border:6px solid #fff">';
  }
})();
function cpEl(el,btn){
  navigator.clipboard.writeText(el.textContent.trim()).then(function(){
    if(btn){var t=btn.textContent;btn.textContent='✓ Copied';setTimeout(function(){btn.textContent=t;},1800);}
    else{var c=el.style.color;el.style.color='#4ade80';setTimeout(function(){el.style.color=c;},900);}
  }).catch(function(){});
}
function cpData(btn){
  navigator.clipboard.writeText(btn.dataset.val).then(function(){
    var o=btn.textContent;btn.textContent='✓';setTimeout(function(){btn.textContent=o;},1500);
  }).catch(function(){});
}
</script>
</body>
</html>`

// indexHTML is the fake public landing page served to any unrecognised visitor.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Meridian — Cloud Infrastructure</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#fff;color:#111827}
nav{display:flex;align-items:center;justify-content:space-between;padding:18px 5%;border-bottom:1px solid #f3f4f6;position:sticky;top:0;background:#fff;z-index:10}
.logo{font-weight:800;font-size:1.15rem;color:#4f46e5}
nav ul{list-style:none;display:flex;gap:28px}
nav a{text-decoration:none;color:#4b5563;font-size:.9rem;font-weight:500}
nav a:hover{color:#4f46e5}
.hero{text-align:center;padding:90px 20px 68px;max-width:720px;margin:0 auto}
.hero h1{font-size:clamp(2rem,5vw,3rem);font-weight:800;line-height:1.12;color:#111827;margin-bottom:20px}
.hero h1 em{font-style:normal;color:#4f46e5}
.hero p{font-size:1.05rem;color:#6b7280;margin-bottom:36px;line-height:1.8;max-width:540px;margin-left:auto;margin-right:auto}
.cta{display:inline-flex;gap:14px;flex-wrap:wrap;justify-content:center}
.btn-p{background:#4f46e5;color:#fff;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:.95rem}
.btn-p:hover{background:#4338ca}
.btn-s{border:1.5px solid #e5e7eb;color:#374151;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:.95rem}
.features{background:#f9fafb;padding:72px 20px}
.ft-wrap{max-width:920px;margin:0 auto}
.ft-head{text-align:center;font-size:1.5rem;font-weight:800;color:#111827;margin-bottom:38px}
.ft-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:18px}
.ft{background:#fff;border-radius:12px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.06);border:1px solid #f3f4f6}
.ft-icon{font-size:1.6rem;margin-bottom:11px}
.ft h3{font-size:.95rem;font-weight:700;margin-bottom:7px;color:#111827}
.ft p{font-size:.83rem;color:#6b7280;line-height:1.65}
footer{text-align:center;padding:28px;color:#9ca3af;font-size:.8rem;border-top:1px solid #f3f4f6}
</style>
</head>
<body>
<nav>
  <span class="logo">▲ Meridian</span>
  <ul>
    <li><a href="#">Products</a></li>
    <li><a href="#">Pricing</a></li>
    <li><a href="#">Docs</a></li>
    <li><a href="#">Blog</a></li>
  </ul>
</nav>
<div class="hero">
  <h1>Infrastructure for<br><em>modern applications</em></h1>
  <p>Deploy globally in seconds. Scale automatically with demand. Built for developers who ship fast and need to stay reliable.</p>
  <div class="cta">
    <a class="btn-p" href="#">Get Started Free</a>
    <a class="btn-s" href="#">View Documentation</a>
  </div>
</div>
<section class="features">
  <div class="ft-wrap">
    <p class="ft-head">Everything you need to ship</p>
    <div class="ft-grid">
      <div class="ft"><div class="ft-icon">⚡</div><h3>Edge Deployment</h3><p>Deploy to 30+ regions worldwide with a single command. Sub-50ms latency globally.</p></div>
      <div class="ft"><div class="ft-icon">🔒</div><h3>Zero-Trust Security</h3><p>End-to-end encryption, automatic TLS certificates, and DDoS protection included.</p></div>
      <div class="ft"><div class="ft-icon">📈</div><h3>Auto Scaling</h3><p>Scale from zero to millions of requests. Pay only for what you actually use.</p></div>
      <div class="ft"><div class="ft-icon">🔧</div><h3>CI/CD Built-In</h3><p>Connect your Git repo and ship on every push. One-click rollbacks always available.</p></div>
    </div>
  </div>
</section>
<footer>© 2024 Meridian Technologies, Inc. &nbsp;·&nbsp; Terms &nbsp;·&nbsp; Privacy &nbsp;·&nbsp; Status</footer>
</body>
</html>`

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	serviceHost := envOr("SERVICE_HOST", "0.0.0.0")
	servicePort := envOr("SERVICE_PORT", envOr("PORT", "8080"))
	serviceEndpoint := envOr("SERVICE_ENDPOINT", "/api/v1/metrics")
	internalPort := envOr("INTERNAL_PORT", "18080")
	adminPath := envOr("ADMIN_PATH", "/admin")
	resolverPath := envOr("RESOLVER_PATH", "/dns-query")
	internalAddr := "127.0.0.1:" + internalPort
	listenAddr := serviceHost + ":" + servicePort

	if serviceEndpoint == adminPath {
		log.Fatalf("[metrics] SERVICE_ENDPOINT and ADMIN_PATH must be different (both are %q)", serviceEndpoint)
	}
	if resolverPath != "" && (resolverPath == serviceEndpoint || resolverPath == adminPath) {
		log.Fatalf("[metrics] RESOLVER_PATH %q conflicts with SERVICE_ENDPOINT or ADMIN_PATH", resolverPath)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(serviceEndpoint, makeWsHandler(internalAddr))
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc(adminPath, makePortalHandler())
	if resolverPath != "" {
		mux.HandleFunc(resolverPath, makeDNSHandler())
	}
	mux.HandleFunc("/", indexHandler)

	adminToken := computeAdminToken()
	log.Printf("[metrics] listening     : %s", listenAddr)
	log.Printf("[metrics] endpoint      : %s  →  processor %s", serviceEndpoint, internalAddr)
	log.Printf("[metrics] admin panel   : path=%s  token=%s", adminPath, adminToken)
	log.Printf("[metrics] access admin  : https://<your-public-domain>%s?token=%s", adminPath, adminToken)
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

// ── Config portal handlers ────────────────────────────────────────────────────

// computeAdminToken returns ADMIN_TOKEN if set, otherwise derives a 12-char
// hex token from AUTH_SECRET so the admin panel is protected without extra config.
func computeAdminToken() string {
	if p := os.Getenv("ADMIN_TOKEN"); p != "" {
		return p
	}
	h := sha1.New()
	io.WriteString(h, os.Getenv("AUTH_SECRET")+"metrics") //nolint:errcheck
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func makePortalHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != computeAdminToken() {
			// Wrong / missing token → serve fake index (no hint that admin exists)
			indexHandler(w, r)
			return
		}
		data := buildPortalData(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := portalTmpl.Execute(w, data); err != nil {
			log.Printf("[metrics] admin render error: %v", err)
		}
	}
}

// buildPortalData constructs all values for the admin panel from env vars
// and the incoming request (for auto-detecting the public hostname and scheme).
func buildPortalData(r *http.Request) portalData {
	cipher := envOr("SS_CIPHER", "aes-256-gcm")
	ssKey := os.Getenv("SS_KEY")
	serviceEndpoint := envOr("SERVICE_ENDPOINT", "/api/v1/metrics")
	adminPath := envOr("ADMIN_PATH", "/admin")

	// Public hostname: explicit env var takes priority, then the HTTP Host header.
	// Strip any port from the Host header — extPort is sourced separately.
	extHost := os.Getenv("PUBLIC_HOST")
	if extHost == "" {
		extHost = r.Host
		if h, _, err := net.SplitHostPort(extHost); err == nil {
			extHost = h
		}
	}
	extPort := envOr("PUBLIC_PORT", "443")
	extTLS := envOr("PUBLIC_TLS", "true") == "true"

	// Determine the scheme the client actually used to reach us.
	// PaaS platforms terminate TLS and forward plain HTTP, but set X-Forwarded-Proto.
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}

	// Build the full admin URL — omit port when it matches the scheme default
	// so PaaS URLs look like https://myapp.railway.app/admin?token=... (no :443).
	hostPart := extHost
	if (scheme == "https" && extPort != "443") || (scheme == "http" && extPort != "80") {
		hostPart = extHost + ":" + extPort
	}
	adminURL := fmt.Sprintf("%s://%s%s?token=%s", scheme, hostPart, adminPath, computeAdminToken())

	// DoH URL: same scheme+host as the admin panel, just a different path.
	resolverPath := envOr("RESOLVER_PATH", "/dns-query")
	dohURL := ""
	if resolverPath != "" {
		dohURL = fmt.Sprintf("%s://%s%s", scheme, hostPart, resolverPath)
	}

	// External DoH for client configuration.
	// We recommend Cloudflare here — it is reliably fast and doesn't need to be
	// routed through the service (the DoH server is the same host as the service,
	// so routing it through the service would be circular).
	extDoHURL := envOr("EXT_DOH", "https://cloudflare-dns.com/dns-query")

	ssURI := buildSSURI(extHost, extPort, serviceEndpoint, cipher, ssKey, extTLS)

	return portalData{
		SSURI:        ssURI,
		HasSS:        ssKey != "",
		PortalURL:    adminURL,
		DoHURL:       dohURL,
		ExtDoHURL:    extDoHURL,
		ExtHost:      extHost,
		ExtPort:      extPort,
		ExtTLS:       extTLS,
		Cipher:       cipher,
		SSKey:        ssKey,
		WSPath:       serviceEndpoint,
		AuthUser:     os.Getenv("AUTH_USER"),
		AuthSecret:   os.Getenv("AUTH_SECRET"),
	}
}

// buildSSURI constructs the service configuration URI in the extended
// SIP002 format for client applications.
//
//	ss://BASE64URL(cipher:key)@host:port?type=ws&path=PATH&host=HOST[&security=tls&sni=HOST]&domain_strategy=remote#metrics
//
// The domain_strategy=remote parameter tells the client to pass
// domain names through the service as-is rather than
// pre-resolving them locally. This ensures the service
// resolves all domains for optimal routing.
func buildSSURI(extHost, extPort, serviceEndpoint, cipher, ssKey string, tls bool) string {
	if ssKey == "" {
		return ""
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + ssKey))

	params := url.Values{}
	params.Set("type", "ws")
	params.Set("path", serviceEndpoint)
	params.Set("host", extHost)
	if tls {
		params.Set("security", "tls")
		params.Set("sni", extHost)
	}
	// domain_strategy=remote prevents client-side DNS pre-resolution.
	// Without this, the client resolves domains before sending to the
	// service, which sends IPv4 addresses through the connection and
	// bypasses the service's DNS resolution entirely.
	params.Set("domain_strategy", "remote")

	return fmt.Sprintf("ss://%s@%s:%s?%s#metrics", userinfo, extHost, extPort, params.Encode())
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
		// Non-WebSocket requests to the endpoint get the fake landing page
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			indexHandler(w, r)
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
