package tlsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrBusy is returned when a certificate run is already in progress.
var ErrBusy = errors.New("Es läuft bereits eine Zertifikatsanforderung.")

const maxLogLines = 300

// CertInfo describes the certificate currently in use.
type CertInfo struct {
	Domains    []string  `json:"domains"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
	RenewAfter time.Time `json:"renewAfter"`
	Directory  string    `json:"directory,omitempty"`
}

// RunInfo is the outcome (and log) of the latest certificate run.
type RunInfo struct {
	Trigger  string     `json:"trigger"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	OK       bool       `json:"ok"`
	Error    string     `json:"error,omitempty"`
	Log      []string   `json:"log"`
}

// Status is the state shown in the admin UI.
type Status struct {
	Enabled     bool       `json:"enabled"`  // configured in the UI
	Active      bool       `json:"active"`   // new connections are served with TLS
	External    bool       `json:"external"` // TLS_CERT/TLS_KEY are set, the UI settings are ignored
	Cert        *CertInfo  `json:"cert,omitempty"`
	Running     bool       `json:"running"`
	NeedsIssue  string     `json:"needsIssue,omitempty"` // reason why a new certificate is due
	NextAttempt *time.Time `json:"nextAttempt,omitempty"`
	LastRun     *RunInfo   `json:"lastRun,omitempty"`
}

// Manager owns the TLS configuration and certificate.
type Manager struct {
	dir      string
	acmeHTTP *http.Client // nil = default; replaced in tests

	mu       sync.RWMutex
	cfg      Config
	cert     *tls.Certificate
	info     *CertInfo
	static   *tls.Certificate
	staticCI *CertInfo
	running  bool
	changed  chan struct{} // closed (and reset) when the TLS state changes, see Changed
	last     *RunInfo
	failures int
	next     time.Time
}

// New loads tls.json and an existing certificate from configDir.
func New(configDir string) (*Manager, error) {
	m := &Manager{dir: configDir}
	cfg, err := loadConfig(m.configPath())
	if err != nil {
		return nil, err
	}
	m.cfg = cfg
	if err := m.loadCert(); err != nil {
		log.Printf("tls: gespeichertes Zertifikat nicht lesbar (wird neu angefordert): %v", err)
	}
	return m, nil
}

func (m *Manager) configPath() string { return filepath.Join(m.dir, "tls.json") }
func (m *Manager) certDir() string    { return filepath.Join(m.dir, "tls") }

type certMeta struct {
	Directory string `json:"directory"`
}

func leafInfo(c *tls.Certificate) (*CertInfo, error) {
	if len(c.Certificate) == 0 {
		return nil, errors.New("leere Zertifikatskette")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" {
		issuer = leaf.Issuer.String()
	}
	return &CertInfo{Domains: leaf.DNSNames, Issuer: issuer, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
}

func (m *Manager) loadCert() error {
	crt, err := tls.LoadX509KeyPair(filepath.Join(m.certDir(), "cert.pem"), filepath.Join(m.certDir(), "key.pem"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := leafInfo(&crt)
	if err != nil {
		return err
	}
	if b, err := os.ReadFile(filepath.Join(m.certDir(), "meta.json")); err == nil {
		var meta certMeta
		if json.Unmarshal(b, &meta) == nil {
			info.Directory = meta.Directory
		}
	}
	m.cert, m.info = &crt, info
	return nil
}

// LoadStatic uses a fixed certificate (TLS_CERT/TLS_KEY). It takes precedence
// over the certificate managed through the UI.
func (m *Manager) LoadStatic(certFile, keyFile string) error {
	crt, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	info, err := leafInfo(&crt)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.static, m.staticCI = &crt, info
	m.notifyLocked()
	m.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------- serving

// Active reports whether new connections should be served with TLS.
func (m *Manager) Active() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeLocked()
}

func (m *Manager) activeLocked() bool {
	return m.static != nil || (m.cfg.Enabled && m.cert != nil)
}

func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch {
	case m.static != nil:
		return m.static, nil
	case m.cfg.Enabled && m.cert != nil:
		return m.cert, nil
	}
	return nil, errors.New("kein Zertifikat vorhanden")
}

// TLSConfig is used for every accepted TLS connection.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// ---------------------------------------------------------------- settings

// Config returns a copy of the current settings (including the API key).
func (m *Manager) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cfg
	c.Domains = append([]string(nil), c.Domains...)
	return c
}

// resolveKey keeps the stored API key when the submitted one is empty.
func (m *Manager) resolveKey(c *Config) {
	if c.PowerDNS.APIKey == "" {
		m.mu.RLock()
		c.PowerDNS.APIKey = m.cfg.PowerDNS.APIKey
		m.mu.RUnlock()
	}
}

// SetConfig validates and stores new settings. An empty API key keeps the
// stored one. If TLS is enabled and the certificate does not match anymore, a
// new one is requested in the background.
func (m *Manager) SetConfig(c Config) error {
	if m.External() {
		return invalid("TLS wird über die Umgebungsvariablen TLS_CERT/TLS_KEY gesteuert – die Einstellungen hier sind deaktiviert.")
	}
	m.resolveKey(&c)
	if err := c.Normalize(c.Enabled); err != nil {
		return err
	}
	if err := saveConfig(m.configPath(), c); err != nil {
		return err
	}
	m.mu.Lock()
	m.cfg = c
	m.next = time.Time{}
	m.failures = 0
	m.notifyLocked()
	m.mu.Unlock()
	if c.Enabled {
		m.maybeIssue("Einstellungen geändert")
	}
	return nil
}

// External reports whether a static certificate from the environment is in use.
func (m *Manager) External() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.static != nil
}

// Status returns the current state.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{Enabled: m.cfg.Enabled, Active: m.activeLocked(), External: m.static != nil, Running: m.running}
	switch {
	case m.static != nil:
		ci := *m.staticCI
		st.Cert = &ci
	case m.info != nil:
		ci := *m.info
		ci.RenewAfter = ci.NotAfter.AddDate(0, 0, -m.cfg.RenewBeforeDays)
		st.Cert = &ci
	}
	st.NeedsIssue = m.needsIssueLocked(time.Now())
	if !m.next.IsZero() && m.next.After(time.Now()) {
		n := m.next
		st.NextAttempt = &n
	}
	if m.last != nil {
		l := *m.last
		l.Log = append([]string(nil), m.last.Log...)
		st.LastRun = &l
	}
	return st
}

// needsIssueLocked returns why a new certificate is due, or "".
func (m *Manager) needsIssueLocked(now time.Time) string {
	if !m.cfg.Enabled || m.static != nil {
		return ""
	}
	if m.cert == nil || m.info == nil {
		return "Es ist noch kein Zertifikat vorhanden."
	}
	if !sameDomains(m.info.Domains, m.cfg.Domains) {
		return "Die Domains haben sich geändert."
	}
	if m.info.Directory != "" && m.info.Directory != m.cfg.DirectoryURL() {
		return "Die Zertifizierungsstelle wurde gewechselt."
	}
	if left := m.info.NotAfter.Sub(now); left < time.Duration(m.cfg.RenewBeforeDays)*24*time.Hour {
		if left <= 0 {
			return "Das Zertifikat ist abgelaufen."
		}
		return fmt.Sprintf("Das Zertifikat läuft in %d Tagen ab.", int(left.Hours()/24))
	}
	return ""
}

func sameDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if !strings.EqualFold(x[i], y[i]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- issuing

// Run checks periodically whether a certificate has to be requested or
// renewed. It returns when ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.mu.RLock()
		due := m.needsIssueLocked(time.Now()) != "" && !time.Now().Before(m.next)
		m.mu.RUnlock()
		if due {
			m.maybeIssue("automatisch")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) maybeIssue(trigger string) {
	if err := m.Issue(trigger); err != nil && !errors.Is(err, ErrBusy) {
		log.Printf("tls: %v", err)
	}
}

// Issue starts a certificate run in the background.
func (m *Manager) Issue(trigger string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return ErrBusy
	}
	cfg := m.cfg
	if m.static != nil {
		m.mu.Unlock()
		return invalid("TLS wird über die Umgebungsvariablen TLS_CERT/TLS_KEY gesteuert.")
	}
	if err := cfg.Normalize(true); err != nil {
		m.mu.Unlock()
		return err
	}
	m.running = true
	m.last = &RunInfo{Trigger: trigger, Started: time.Now()}
	m.mu.Unlock()
	go m.run(cfg)
	return nil
}

func (m *Manager) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	log.Printf("tls: %s", line)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return
	}
	if len(m.last.Log) >= maxLogLines {
		m.last.Log = m.last.Log[1:]
	}
	m.last.Log = append(m.last.Log, time.Now().Format("15:04:05")+"  "+line)
}

func (m *Manager) run(cfg Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	m.logf("Zertifikatsanforderung gestartet")
	res, err := m.obtain(ctx, cfg, m.logf)
	if err == nil {
		err = m.install(cfg, res)
	}
	m.mu.Lock()
	now := time.Now()
	m.running = false
	m.last.Finished = &now
	if err != nil {
		m.failures++
		backoff := time.Hour << min(m.failures-1, 4) // 1h … 16h
		backoff = min(backoff, 12*time.Hour)
		m.next = now.Add(backoff)
		m.last.Error = err.Error()
	} else {
		m.failures = 0
		m.next = time.Time{}
		m.last.OK = true
	}
	m.mu.Unlock()
	if err != nil {
		m.logf("FEHLER: %v", err)
	} else {
		m.logf("Fertig – das neue Zertifikat ist aktiv")
	}
}

// install stores the certificate on disk and switches to it.
func (m *Manager) install(cfg Config, res *issued) error {
	crt, err := tls.X509KeyPair(res.certPEM, res.keyPEM)
	if err != nil {
		return fmt.Errorf("ausgestelltes Zertifikat unbrauchbar: %w", err)
	}
	info, err := leafInfo(&crt)
	if err != nil {
		return err
	}
	info.Directory = cfg.DirectoryURL()
	dir := m.certDir()
	// Key first: a crash in between leaves an old cert with a new key, which
	// fails to load and triggers a fresh request on the next start.
	if err := writeFileAtomic(filepath.Join(dir, "key.pem"), res.keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "cert.pem"), res.certPEM, 0o644); err != nil {
		return err
	}
	meta, _ := json.Marshal(certMeta{Directory: info.Directory})
	if err := writeFileAtomic(filepath.Join(dir, "meta.json"), meta, 0o600); err != nil {
		return err
	}
	m.mu.Lock()
	m.cert, m.info = &crt, info
	m.notifyLocked()
	m.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------- DNS check

// DomainCheck is the result of testing the PowerDNS access for one domain.
type DomainCheck struct {
	Domain string `json:"domain"`
	Zone   string `json:"zone,omitempty"`
	Error  string `json:"error,omitempty"`
}

// CheckDNS verifies the PowerDNS settings in c (an empty API key falls back
// to the stored one) without changing any record.
func (m *Manager) CheckDNS(ctx context.Context, c Config) ([]DomainCheck, error) {
	m.resolveKey(&c)
	if err := c.Normalize(false); err != nil {
		return nil, err
	}
	if c.PowerDNS.URL == "" || c.PowerDNS.APIKey == "" {
		return nil, invalid("Bitte PowerDNS-API-URL und API-Key angeben.")
	}
	if len(c.Domains) == 0 {
		return nil, invalid("Bitte mindestens eine Domain angeben.")
	}
	p := newPDNS(c.PowerDNS)
	if c.PowerDNS.Zone != "" {
		z := fqdn(c.PowerDNS.Zone)
		if err := p.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(z), nil, nil); err != nil {
			return nil, err
		}
	} else if _, err := p.ListZones(ctx); err != nil {
		return nil, err
	}
	var out []DomainCheck
	for _, d := range c.Domains {
		dc := DomainCheck{Domain: d}
		z, err := p.FindZone(ctx, "_acme-challenge."+strings.TrimPrefix(d, "*."))
		if err != nil {
			dc.Error = err.Error()
		} else {
			dc.Zone = strings.TrimSuffix(z.Name, ".")
		}
		out = append(out, dc)
	}
	return out, nil
}

// ---------------------------------------------------------------- helpers

// HostMatches reports whether host is covered by the certificate name (which
// may be a one-label wildcard like *.example.com).
func HostMatches(name, host string) bool {
	name, host = strings.ToLower(name), strings.ToLower(host)
	if name == host {
		return true
	}
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		if h, ok := strings.CutSuffix(host, "."+rest); ok && h != "" && !strings.Contains(h, ".") {
			return true
		}
	}
	return false
}

// certNames returns the names of the certificate in use.
func (m *Manager) certNames() (active bool, names []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch {
	case m.static != nil:
		names = m.staticCI.Domains
	case m.info != nil:
		names = m.info.Domains
	}
	return m.activeLocked(), names
}

// CertHost returns the host name browsers and clients should use while TLS is
// active: host itself if the certificate covers it, otherwise the first
// non-wildcard certificate name, otherwise host unchanged.
func (m *Manager) CertHost(host string) string {
	_, names := m.certNames()
	for _, n := range names {
		if HostMatches(n, host) {
			return host
		}
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	return host
}

// AdjustPublicURL turns the configured gateway address into one that works
// while TLS is active: https, a host covered by the certificate, and
// tlsPort, the port of the HTTPS gateway listener.
func (m *Manager) AdjustPublicURL(raw, tlsPort string) string {
	active, _ := m.certNames()
	if !active || raw == "" || strings.HasPrefix(raw, "https://") {
		// raw == "": the UI derives the address from the page it was loaded from
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme = "https"
	u.Host = joinHostPort(m.CertHost(u.Hostname()), tlsPort)
	return strings.TrimRight(u.String(), "/")
}
