package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeDomains(t *testing.T) {
	got, err := NormalizeDomains([]string{" Backup.Example.com. ", "*.example.com", "backup.example.com", ""})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "backup.example.com,*.example.com" {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"localhost", "a.*.example.com", "exa mple.com", "192.168.1.1", "bücher.example.com", "-a.example.com", "*example.com"} {
		if _, err := NormalizeDomains([]string{bad}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestConfigNormalize(t *testing.T) {
	c := DefaultConfig()
	if err := c.Normalize(true); err == nil {
		t.Fatal("empty config must not be valid when enabled")
	}
	c.Domains = []string{"backup.example.com"}
	c.PowerDNS.URL = "http://pdns:8081/api/v1/"
	c.PowerDNS.APIKey = "secret"
	if err := c.Normalize(true); err == nil || !strings.Contains(err.Error(), "Nutzungsbedingungen") {
		t.Fatalf("ToS must be required: %v", err)
	}
	c.AcceptTOS = true
	if err := c.Normalize(true); err != nil {
		t.Fatal(err)
	}
	if c.PowerDNS.URL != "http://pdns:8081" {
		t.Fatalf("url not normalized: %q", c.PowerDNS.URL)
	}
	c.PowerDNS.DNSServer = "ns1.example.com/x"
	if err := c.Normalize(true); err == nil {
		t.Fatal("bad dns server accepted")
	}
	c.PowerDNS.DNSServer = ""
	c.CA = CACustom
	c.CustomDirectory = "ftp://x"
	if err := c.Normalize(true); err == nil {
		t.Fatal("bad custom directory accepted")
	}
	c.CA = CAStaging
	if err := c.Normalize(true); err != nil || c.DirectoryURL() != LetsEncryptStaging || c.CustomDirectory != "" {
		t.Fatalf("staging: %v %q", err, c.DirectoryURL())
	}
	d := DefaultConfig() // a draft with TLS off may be incomplete
	if err := d.Normalize(false); err != nil {
		t.Fatal(err)
	}
}

func TestPickZone(t *testing.T) {
	zones := []pdnsZone{{ID: "example.com.", Name: "example.com."}, {ID: "sub.example.com.", Name: "sub.example.com."}, {ID: "notexample.com.", Name: "notexample.com."}}
	for name, want := range map[string]string{
		"_acme-challenge.backup.example.com":     "example.com.",
		"_acme-challenge.host.sub.example.com":   "sub.example.com.",
		"_acme-challenge.sub.example.com.":       "sub.example.com.",
		"_acme-challenge.other.notexample.com":   "notexample.com.",
		"_acme-challenge.example.com":            "example.com.",
		"_acme-challenge.example.org":            "",
		"_acme-challenge.xnotexample.com.local.": "",
	} {
		z, ok := pickZone(zones, name)
		if want == "" && ok || want != "" && z.Name != want {
			t.Errorf("%s: got %v %v, want %q", name, z, ok, want)
		}
	}
}

type fakePDNS struct {
	mu      sync.Mutex
	patches []map[string]any
	zones   []pdnsZone
}

func (f *fakePDNS) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/servers/localhost/zones":
			json.NewEncoder(w).Encode(f.zones)
		case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/api/v1/servers/localhost/zones/"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			body["_path"] = r.URL.Path
			f.mu.Lock()
			f.patches = append(f.patches, body)
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"Not Found"}`)
		}
	})
}

func TestPowerDNSClient(t *testing.T) {
	f := &fakePDNS{zones: []pdnsZone{{ID: "example.com.", Name: "example.com."}}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	ctx := context.Background()
	c := newPDNS(PowerDNS{URL: srv.URL, APIKey: "k", ServerID: "localhost", TTL: 60})
	z, err := c.FindZone(ctx, "_acme-challenge.backup.example.com")
	if err != nil || z.ID != "example.com." {
		t.Fatalf("FindZone: %v %v", z, err)
	}
	if _, err := c.FindZone(ctx, "_acme-challenge.example.org"); err == nil {
		t.Fatal("zone for foreign domain found")
	}
	if err := c.SetTXT(ctx, z, "_acme-challenge.Example.com", []string{"v1", "v2"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteTXT(ctx, z, "_acme-challenge.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 2 {
		t.Fatalf("patches: %v", f.patches)
	}
	set := f.patches[0]["rrsets"].([]any)[0].(map[string]any)
	if set["name"] != "_acme-challenge.example.com." || set["type"] != "TXT" || set["changetype"] != "REPLACE" || set["ttl"] != float64(60) {
		t.Fatalf("bad rrset: %v", set)
	}
	recs := set["records"].([]any)
	if len(recs) != 2 || recs[0].(map[string]any)["content"] != `"v1"` {
		t.Fatalf("bad records: %v", recs)
	}
	del := f.patches[1]["rrsets"].([]any)[0].(map[string]any)
	if del["changetype"] != "DELETE" {
		t.Fatalf("bad delete: %v", del)
	}

	bad := newPDNS(PowerDNS{URL: srv.URL, APIKey: "wrong", ServerID: "localhost"})
	if _, err := bad.ListZones(ctx); err == nil || !strings.Contains(err.Error(), "API-Key abgelehnt") {
		t.Fatalf("expected auth error, got %v", err)
	}

	// An explicitly configured zone must contain the name.
	zc := newPDNS(PowerDNS{URL: srv.URL, APIKey: "k", ServerID: "localhost", Zone: "example.com"})
	if z, err := zc.FindZone(ctx, "_acme-challenge.a.example.com"); err != nil || z.ID != "example.com." {
		t.Fatalf("configured zone: %v %v", z, err)
	}
	if _, err := zc.FindZone(ctx, "_acme-challenge.a.example.org"); err == nil {
		t.Fatal("name outside configured zone accepted")
	}
}

func TestPresentTXTCleansUp(t *testing.T) {
	f := &fakePDNS{zones: []pdnsZone{{ID: "example.com.", Name: "example.com."}}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := newPDNS(PowerDNS{URL: srv.URL, APIKey: "k", ServerID: "localhost", TTL: 60})
	var logs []string
	logf := func(format string, a ...any) { logs = append(logs, format) }

	// second name has no zone: the first one must still be cleaned up
	cleanup, err := presentTXT(context.Background(), c, []txtRecord{
		{name: "_acme-challenge.a.example.com", values: []string{"x"}},
		{name: "_acme-challenge.b.example.org", values: []string{"y"}},
	}, logf)
	if err == nil {
		t.Fatal("expected error for missing zone")
	}
	cleanup(context.Background())
	if len(f.patches) != 2 {
		t.Fatalf("expected set + delete, got %d patches", len(f.patches))
	}
}

func TestHostMatches(t *testing.T) {
	for _, c := range []struct {
		name, host string
		want       bool
	}{
		{"backup.example.com", "BACKUP.example.com", true},
		{"*.example.com", "backup.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"backup.example.com", "other.example.com", false},
	} {
		if got := HostMatches(c.name, c.host); got != c.want {
			t.Errorf("HostMatches(%q,%q)=%v", c.name, c.host, got)
		}
	}
}

func selfSigned(t *testing.T, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour),
		DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// setEnabled flips the "enabled" setting like SetConfig does, without
// starting a certificate run.
func setEnabled(m *Manager, on bool) {
	m.mu.Lock()
	m.cfg.Enabled = on
	m.notifyLocked()
	m.mu.Unlock()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestListenersFollowTLSState(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plainAddr, tlsAddr := freeAddr(t), freeAddr(t)
	plainLn, err := m.ListenPlain(plainAddr)
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := m.ListenTLS(tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			io.WriteString(w, "tls=yes")
		} else {
			io.WriteString(w, "tls=no")
		}
	})
	for _, ln := range []net.Listener{plainLn, tlsLn} {
		srv := &http.Server{Handler: h}
		go srv.Serve(ln)
		defer srv.Close()
	}

	get := func(url string) (string, error) {
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		resp, err := c.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	plainOK := func() bool { b, err := get("http://" + plainAddr); return err == nil && b == "tls=no" }
	plainDown := func() bool { _, err := get("http://" + plainAddr); return err != nil }
	tlsOK := func() bool { b, err := get("https://" + tlsAddr); return err == nil && b == "tls=yes" }
	tlsDown := func() bool { _, err := get("https://" + tlsAddr); return err != nil }

	// No TLS: HTTP is served, the HTTPS port is closed.
	if !plainOK() || !tlsDown() {
		t.Fatal("before enabling: want plain up and TLS down")
	}

	// A certificate alone does not switch TLS on ...
	certPEM, keyPEM := selfSigned(t, "backup.example.com")
	cfg := DefaultConfig()
	cfg.Domains = []string{"backup.example.com"}
	if err := m.install(cfg, &issued{certPEM: certPEM, keyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !plainOK() || !tlsDown() {
		t.Fatal("certificate but disabled: want plain up and TLS down")
	}

	// ... enabling it does, without restart: HTTPS opens, HTTP is released.
	setEnabled(m, true)
	eventually(t, "https up", tlsOK)
	eventually(t, "plain down", plainDown)

	// Disabling goes back to plain HTTP only.
	setEnabled(m, false)
	eventually(t, "plain up again", plainOK)
	eventually(t, "https down again", tlsDown)

	// The certificate survives a restart.
	m2, err := New(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	if m2.info == nil || len(m2.info.Domains) != 1 || m2.info.Domains[0] != "backup.example.com" {
		t.Fatalf("certificate not reloaded: %+v", m2.info)
	}
}

func TestListenPlainFailsFastWhenPortBusy(t *testing.T) {
	m, _ := New(t.TempDir())
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := m.ListenPlain(busy.Addr().String()); err == nil {
		t.Fatal("expected an error for a port in use")
	}
	// The HTTPS listener is not bound while TLS is off, so a busy port is no error yet.
	ln, err := m.ListenTLS(busy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

func TestRedirectToHTTPSAndDenyPlain(t *testing.T) {
	m, _ := New(t.TempDir())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "app") })
	redirect := m.RedirectToHTTPS(next, "8443")
	deny := m.DenyPlain(next)
	do := func(h http.Handler, host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://"+host+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := do(redirect, "nas:8080", "/x"); w.Body.String() != "app" {
		t.Fatalf("TLS off: no redirect expected, got %d %q", w.Code, w.Body.String())
	}
	if w := do(deny, "nas:8000", "/x"); w.Body.String() != "app" {
		t.Fatalf("TLS off: gateway must work, got %d", w.Code)
	}

	certPEM, keyPEM := selfSigned(t, "backup.example.com", "*.lan.example.com")
	_ = m.install(DefaultConfig(), &issued{certPEM: certPEM, keyPEM: keyPEM})
	setEnabled(m, true)

	for host, want := range map[string]string{
		"backup.example.com:8080": "https://backup.example.com:8443/a/b?c=d",
		"backup.example.com":      "https://backup.example.com:8443/a/b?c=d",
		"nas.lan.example.com:80":  "https://nas.lan.example.com:8443/a/b?c=d",
		"192.168.1.5:8080":        "https://backup.example.com:8443/a/b?c=d", // not covered by the certificate
	} {
		w := do(redirect, host, "/a/b?c=d")
		if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != want {
			t.Errorf("host %q: got %d %q, want %q", host, w.Code, w.Header().Get("Location"), want)
		}
	}
	if w := do(redirect, "backup.example.com:8080", "/healthz"); w.Body.String() != "app" {
		t.Fatalf("/healthz must not be redirected: %d", w.Code)
	}
	if w := do(deny, "backup.example.com:8000", "/x"); w.Code != http.StatusForbidden || w.Body.String() == "app" {
		t.Fatalf("plain gateway must be refused while TLS is active: %d", w.Code)
	}
}

func TestNeedsIssue(t *testing.T) {
	m, _ := New(t.TempDir())
	now := time.Now()
	if m.needsIssueLocked(now) != "" {
		t.Fatal("disabled TLS must not request certificates")
	}
	m.cfg.Enabled = true
	m.cfg.Domains = []string{"a.example.com"}
	if m.needsIssueLocked(now) == "" {
		t.Fatal("missing certificate must be requested")
	}
	certPEM, keyPEM := selfSigned(t, "a.example.com")
	if err := m.install(m.cfg, &issued{certPEM: certPEM, keyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	if r := m.needsIssueLocked(now); r != "" {
		t.Fatalf("fresh certificate: %q", r)
	}
	m.cfg.Domains = []string{"a.example.com", "b.example.com"}
	if m.needsIssueLocked(now) == "" {
		t.Fatal("changed domains must trigger a new certificate")
	}
	m.cfg.Domains = []string{"a.example.com"}
	m.cfg.CA = CAStaging
	if m.needsIssueLocked(now) == "" {
		t.Fatal("changed CA must trigger a new certificate")
	}
	m.cfg.CA = CAProduction
	m.info.Directory = LetsEncryptProduction
	if r := m.needsIssueLocked(now.Add(50 * 24 * time.Hour)); !strings.Contains(r, "läuft in") {
		t.Fatalf("expiring certificate: %q", r)
	}
	if r := m.needsIssueLocked(now.Add(70 * 24 * time.Hour)); !strings.Contains(r, "abgelaufen") {
		t.Fatalf("expired certificate: %q", r)
	}
}

func TestSetConfigKeepsAPIKey(t *testing.T) {
	m, _ := New(t.TempDir())
	cfg := DefaultConfig()
	cfg.PowerDNS.URL = "http://pdns:8081"
	cfg.PowerDNS.APIKey = "secret"
	if err := m.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.PowerDNS.APIKey = "" // the UI never sends the key back
	cfg.Email = "a@example.com"
	if err := m.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := m.Config().PowerDNS.APIKey; got != "secret" {
		t.Fatalf("API key lost: %q", got)
	}
	m2, err := New(m.dir)
	if err != nil || m2.Config().PowerDNS.APIKey != "secret" || m2.Config().Email != "a@example.com" {
		t.Fatalf("not persisted: %v %+v", err, m2.Config())
	}
	cfg.Enabled = true // incomplete (no domain)
	var ve *ValidationError
	if err := m.SetConfig(cfg); !errors.As(err, &ve) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestAdjustPublicURL(t *testing.T) {
	m, _ := New(t.TempDir())
	if got := m.AdjustPublicURL("http://nas:8000", "8444"); got != "http://nas:8000" {
		t.Fatalf("inactive TLS must not change the URL: %q", got)
	}
	certPEM, keyPEM := selfSigned(t, "backup.example.com", "*.lan.example.com")
	_ = m.install(DefaultConfig(), &issued{certPEM: certPEM, keyPEM: keyPEM})
	m.cfg.Enabled = true
	for in, want := range map[string]string{
		"":                                 "",
		"https://x.example.com/rest":       "https://x.example.com/rest",
		"http://backup.example.com:8000":   "https://backup.example.com:8444",
		"http://nas.lan.example.com:8000/": "https://nas.lan.example.com:8444",
		"http://truenas.local:8000":        "https://backup.example.com:8444",
		"http://truenas.local:8000/restic": "https://backup.example.com:8444/restic",
	} {
		if got := m.AdjustPublicURL(in, "8444"); got != want {
			t.Errorf("AdjustPublicURL(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestStaticCertificateTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	m, _ := New(dir)
	certPEM, keyPEM := selfSigned(t, "static.example.com")
	if err := writeFileAtomic(dir+"/c.pem", certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(dir+"/k.pem", keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadStatic(dir+"/c.pem", dir+"/k.pem"); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if !st.Active || !st.External || st.Cert == nil || st.Cert.Domains[0] != "static.example.com" {
		t.Fatalf("status: %+v", st)
	}
	var ve *ValidationError
	if err := m.SetConfig(DefaultConfig()); !errors.As(err, &ve) {
		t.Fatalf("settings must be locked with a static certificate: %v", err)
	}
}
