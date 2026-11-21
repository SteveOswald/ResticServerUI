// Package tlsmgr obtains and renews TLS certificates from an ACME CA (Let's
// Encrypt) using the DNS-01 challenge with PowerDNS, and serves them to the
// web UI and the restic gateway. All settings live in CONFIG_DIR/tls.json and
// are edited through the admin UI.
package tlsmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Certificate authorities selectable in the UI.
const (
	CAProduction = "production"
	CAStaging    = "staging"
	CACustom     = "custom"

	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ValidationError is returned for invalid settings; its message is user facing.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// PowerDNS describes the PowerDNS Authoritative Server HTTP API used to
// publish the _acme-challenge TXT records.
type PowerDNS struct {
	URL                string `json:"url"`                // e.g. http://pdns:8081
	APIKey             string `json:"apiKey"`             // X-API-Key
	ServerID           string `json:"serverId"`           // default "localhost"
	Zone               string `json:"zone"`               // empty = detect per domain
	TTL                int    `json:"ttl"`                // TTL of the TXT records
	PropagationSeconds int    `json:"propagationSeconds"` // minimum wait before validation
	DNSServer          string `json:"dnsServer"`          // optional resolver for the pre-check, host[:port]
}

// Config is the persisted TLS configuration.
type Config struct {
	Enabled         bool     `json:"enabled"`
	Domains         []string `json:"domains"`
	Email           string   `json:"email"`
	CA              string   `json:"ca"`
	CustomDirectory string   `json:"customDirectory"`
	AcceptTOS       bool     `json:"acceptTos"`
	RenewBeforeDays int      `json:"renewBeforeDays"`
	PowerDNS        PowerDNS `json:"powerdns"`
}

// DefaultConfig returns the settings used before anything has been saved.
func DefaultConfig() Config {
	return Config{
		CA:              CAProduction,
		RenewBeforeDays: 30,
		PowerDNS:        PowerDNS{ServerID: "localhost", TTL: 60, PropagationSeconds: 30},
	}
}

// DirectoryURL is the ACME directory of the selected CA.
func (c Config) DirectoryURL() string {
	switch c.CA {
	case CAStaging:
		return LetsEncryptStaging
	case CACustom:
		return c.CustomDirectory
	}
	return LetsEncryptProduction
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomains lower-cases, trims and de-duplicates the domain list and
// checks the syntax. Wildcards are only allowed as leading label.
func NormalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" || seen[d] {
			continue
		}
		if !domainRe.MatchString(d) || len(d) > 253 {
			return nil, invalid("Ungültiger Domainname %q. Erlaubt sind z. B. backup.example.com oder *.example.com (Umlaute bitte als Punycode).", d)
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) > 20 {
		return nil, invalid("Maximal 20 Domains pro Zertifikat.")
	}
	return out, nil
}

func normalizeServerAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.ContainsAny(s, "/ \t") {
		return "", invalid("Ungültiger DNS-Server %q – erwartet wird host oder host:port.", s)
	}
	return s, nil
}

// Normalize cleans up and validates c. With strict (TLS enabled) all
// required fields must be present.
func (c *Config) Normalize(strict bool) error {
	var err error
	if c.Domains, err = NormalizeDomains(c.Domains); err != nil {
		return err
	}
	c.Email = strings.TrimSpace(c.Email)
	if c.Email != "" {
		a, err := mail.ParseAddress(c.Email)
		if err != nil || a.Address != c.Email {
			return invalid("Ungültige E-Mail-Adresse.")
		}
	}
	switch c.CA {
	case CAProduction, CAStaging:
		c.CustomDirectory = ""
	case CACustom:
		c.CustomDirectory = strings.TrimSpace(c.CustomDirectory)
		u, err := url.Parse(c.CustomDirectory)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return invalid("Die ACME-Verzeichnis-URL der eigenen CA ist ungültig.")
		}
	default:
		return invalid("Unbekannte Zertifizierungsstelle.")
	}
	if c.RenewBeforeDays == 0 {
		c.RenewBeforeDays = 30
	}
	if c.RenewBeforeDays < 1 || c.RenewBeforeDays > 60 {
		return invalid("„Erneuern vor Ablauf“ muss zwischen 1 und 60 Tagen liegen.")
	}

	p := &c.PowerDNS
	p.URL = strings.TrimRight(strings.TrimSpace(p.URL), "/")
	p.URL = strings.TrimSuffix(p.URL, "/api/v1")
	if p.URL != "" {
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return invalid("Die PowerDNS-API-URL ist ungültig (Beispiel: http://pdns:8081).")
		}
	}
	p.APIKey = strings.TrimSpace(p.APIKey)
	p.ServerID = strings.TrimSpace(p.ServerID)
	if p.ServerID == "" {
		p.ServerID = "localhost"
	}
	if strings.ContainsAny(p.ServerID, "/ ?#") {
		return invalid("Ungültige PowerDNS-Server-ID.")
	}
	p.Zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Zone), "."))
	if p.Zone != "" && !domainRe.MatchString(p.Zone) {
		return invalid("Ungültiger Zonenname %q.", p.Zone)
	}
	if p.TTL == 0 {
		p.TTL = 60
	}
	if p.TTL < 1 || p.TTL > 86400 {
		return invalid("Die TTL muss zwischen 1 und 86400 Sekunden liegen.")
	}
	if p.PropagationSeconds < 0 || p.PropagationSeconds > 900 {
		return invalid("Die Wartezeit muss zwischen 0 und 900 Sekunden liegen.")
	}
	if p.DNSServer, err = normalizeServerAddr(p.DNSServer); err != nil {
		return err
	}

	if strict {
		switch {
		case len(c.Domains) == 0:
			return invalid("Bitte mindestens eine Domain angeben.")
		case !c.AcceptTOS:
			return invalid("Die Nutzungsbedingungen der Zertifizierungsstelle müssen akzeptiert werden.")
		case p.URL == "":
			return invalid("Bitte die PowerDNS-API-URL angeben.")
		case p.APIKey == "":
			return invalid("Bitte den PowerDNS-API-Key angeben.")
		}
	}
	return nil
}

// ---------------------------------------------------------------- persistence

func loadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Normalize(false); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func saveConfig(path string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

// writeFileAtomic writes data to a temporary file next to path and renames it.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
