package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const userAgent = "restic-server-ui"

type issued struct {
	certPEM, keyPEM []byte
}

type txtRecord struct {
	name   string // without trailing dot
	values []string
}

type pendingAuthz struct {
	url    string
	domain string
	chal   *acme.Challenge
	rec    string // TXT name
}

func (m *Manager) accountKey(directory string) (*ecdsa.PrivateKey, error) {
	sum := sha256.Sum256([]byte(directory))
	path := filepath.Join(m.certDir(), "account-"+hex.EncodeToString(sum[:4])+".key")
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: kein PEM", path)
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// obtain runs the complete ACME order for cfg and returns the PEM encoded
// certificate chain and private key.
func (m *Manager) obtain(ctx context.Context, cfg Config, logf func(string, ...any)) (*issued, error) {
	directory := cfg.DirectoryURL()
	logf("Zertifizierungsstelle: %s", directory)
	logf("Domains: %s", strings.Join(cfg.Domains, ", "))

	accKey, err := m.accountKey(directory)
	if err != nil {
		return nil, fmt.Errorf("ACME-Konto-Schlüssel: %w", err)
	}
	fin := &finalizeFix{base: http.DefaultTransport}
	if m.acmeHTTP != nil && m.acmeHTTP.Transport != nil {
		fin.base = m.acmeHTTP.Transport
	}
	client := &acme.Client{Key: accKey, DirectoryURL: directory, UserAgent: userAgent, HTTPClient: &http.Client{Transport: fin}}

	acct := &acme.Account{}
	if cfg.Email != "" {
		acct.Contact = []string{"mailto:" + cfg.Email}
	}
	_, err = client.Register(ctx, acct, func(string) bool { return cfg.AcceptTOS })
	switch {
	case err == nil:
		logf("ACME-Konto registriert")
	case errors.Is(err, acme.ErrAccountAlreadyExists):
		logf("ACME-Konto vorhanden")
		if acct.Contact != nil {
			if _, uerr := client.UpdateReg(ctx, acct); uerr != nil {
				logf("Hinweis: Kontakt-E-Mail konnte nicht aktualisiert werden: %v", uerr)
			}
		}
	default:
		return nil, fmt.Errorf("ACME-Konto: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(cfg.Domains...))
	if err != nil {
		return nil, fmt.Errorf("Bestellung anlegen: %w", err)
	}

	// Collect the dns-01 challenges. A wildcard and its base domain share the
	// same _acme-challenge name and therefore need two values in one RRset.
	var pending []pendingAuthz
	byName := map[string][]string{}
	for _, zurl := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, zurl)
		if err != nil {
			return nil, fmt.Errorf("Autorisierung abrufen: %w", err)
		}
		if z.Status == acme.StatusValid {
			logf("%s: bereits autorisiert", z.Identifier.Value)
			continue
		}
		var ch *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				ch = c
			}
		}
		if ch == nil {
			return nil, fmt.Errorf("die CA bietet für %s keine DNS-01-Challenge an", z.Identifier.Value)
		}
		val, err := client.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return nil, err
		}
		name := "_acme-challenge." + strings.ToLower(z.Identifier.Value)
		pending = append(pending, pendingAuthz{url: zurl, domain: z.Identifier.Value, chal: ch, rec: name})
		byName[name] = append(byName[name], val)
	}

	if len(pending) > 0 {
		var recs []txtRecord
		for n, v := range byName {
			sort.Strings(v)
			recs = append(recs, txtRecord{name: n, values: v})
		}
		sort.Slice(recs, func(i, j int) bool { return recs[i].name < recs[j].name })

		pdns := newPDNS(cfg.PowerDNS)
		cleanup, err := presentTXT(ctx, pdns, recs, logf)
		defer func() {
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cleanup(cctx)
		}()
		if err != nil {
			return nil, err
		}

		if err := waitPropagation(ctx, recs, cfg.PowerDNS, logf); err != nil {
			return nil, err
		}

		for _, p := range pending {
			logf("%s: Challenge wird bestätigt …", p.domain)
			if _, err := client.Accept(ctx, p.chal); err != nil {
				return nil, fmt.Errorf("Challenge für %s bestätigen: %w", p.domain, err)
			}
		}
		for _, p := range pending {
			if _, err := client.WaitAuthorization(ctx, p.url); err != nil {
				return nil, fmt.Errorf("Validierung von %s fehlgeschlagen: %w", p.domain, err)
			}
			logf("%s: validiert", p.domain)
		}
	}

	// WaitOrder reports the order URL from a Location header, which polling
	// responses do not carry – keep the one from the order creation.
	orderURI, finalizeURL := order.URI, order.FinalizeURL
	ready, err := client.WaitOrder(ctx, orderURI)
	if err != nil {
		return nil, fmt.Errorf("Bestellung nicht bereit: %w", err)
	}
	if ready.FinalizeURL != "" {
		finalizeURL = ready.FinalizeURL
	}
	fin.finalizeURL, fin.orderURL = finalizeURL, orderURI

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: cfg.Domains}, key)
	if err != nil {
		return nil, err
	}
	logf("Zertifikat wird ausgestellt …")
	chain, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("Zertifikat abholen: %w", err)
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &issued{certPEM: certPEM, keyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}, nil
}

// presentTXT publishes the records and returns a function that removes them
// again. The returned function is safe to call even if presenting failed.
func presentTXT(ctx context.Context, pdns *pdnsClient, recs []txtRecord, logf func(string, ...any)) (func(context.Context), error) {
	type placed struct {
		zone pdnsZone
		name string
	}
	var done []placed
	cleanup := func(ctx context.Context) {
		for _, p := range done {
			if err := pdns.DeleteTXT(ctx, p.zone, p.name); err != nil {
				logf("Warnung: TXT-Eintrag %s konnte nicht entfernt werden: %v", p.name, err)
			} else {
				logf("TXT-Eintrag %s entfernt", p.name)
			}
		}
	}
	for _, r := range recs {
		zone, err := pdns.FindZone(ctx, r.name)
		if err != nil {
			return cleanup, err
		}
		if err := pdns.SetTXT(ctx, zone, r.name, r.values); err != nil {
			return cleanup, err
		}
		done = append(done, placed{zone, r.name})
		logf("TXT-Eintrag %s in Zone %s gesetzt", r.name, strings.TrimSuffix(zone.Name, "."))
	}
	return cleanup, nil
}

// waitPropagation waits until the TXT records are visible on the configured
// DNS server (if any) and at least PropagationSeconds have passed.
func waitPropagation(ctx context.Context, recs []txtRecord, p PowerDNS, logf func(string, ...any)) error {
	start := time.Now()
	minWait := time.Duration(p.PropagationSeconds) * time.Second
	if p.DNSServer != "" {
		res := resolverFor(p.DNSServer)
		deadline := time.Now().Add(3 * time.Minute)
		for {
			missing := missingTXT(ctx, res, recs)
			if len(missing) == 0 {
				logf("TXT-Einträge auf %s sichtbar", p.DNSServer)
				break
			}
			if time.Now().After(deadline) {
				logf("Warnung: %s noch nicht auf %s sichtbar – fahre trotzdem fort", strings.Join(missing, ", "), p.DNSServer)
				break
			}
			if err := sleep(ctx, 5*time.Second); err != nil {
				return err
			}
		}
	}
	if rest := minWait - time.Since(start); rest > 0 {
		logf("Warte %d s auf die Verbreitung der DNS-Einträge …", int(rest.Seconds()))
		return sleep(ctx, rest)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func resolverFor(server string) *net.Resolver {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", server)
	}}
}

// missingTXT returns the names whose expected values are not (all) visible yet.
func missingTXT(ctx context.Context, res *net.Resolver, recs []txtRecord) []string {
	var missing []string
	for _, r := range recs {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		got, err := res.LookupTXT(cctx, r.name)
		cancel()
		have := map[string]bool{}
		if err == nil {
			for _, g := range got {
				have[g] = true
			}
		}
		for _, v := range r.values {
			if !have[v] {
				missing = append(missing, r.name)
				break
			}
		}
	}
	return missing
}

// finalizeFix makes x/crypto/acme work with CAs that omit the Location header
// in the response to the finalize request (RFC 8555 does not require it): the
// library polls the order at that Location afterwards.
type finalizeFix struct {
	base                  http.RoundTripper
	finalizeURL, orderURL string
}

func (t *finalizeFix) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil && t.finalizeURL != "" && req.Method == http.MethodPost &&
		req.URL.String() == t.finalizeURL && resp.Header.Get("Location") == "" {
		resp.Header.Set("Location", t.orderURL)
	}
	return resp, err
}
