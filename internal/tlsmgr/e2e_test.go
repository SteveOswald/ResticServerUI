//go:build e2e

package tlsmgr

// End-to-end test against a real ACME server (Pebble) and a real PowerDNS
// (zone "e2e.test", API key "testkey"). It is skipped unless the E2E_*
// variables are set:
//
//	E2E_DIRECTORY  ACME directory of Pebble, e.g. https://pebble:14000/dir
//	E2E_PDNS_URL   PowerDNS API, e.g. http://pdns:8081
//	E2E_DNS        resolver for the pre-check (the PowerDNS DNS port), optional
//
// Pebble must resolve through that PowerDNS (pebble -dnsserver <ip>:53) and
// its minica root must be trusted (SSL_CERT_FILE).

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestE2EIssueWithPebbleAndPowerDNS(t *testing.T) {
	dir, pdnsURL, dns := os.Getenv("E2E_DIRECTORY"), os.Getenv("E2E_PDNS_URL"), os.Getenv("E2E_DNS")
	if dir == "" || pdnsURL == "" {
		t.Skip("E2E_DIRECTORY / E2E_PDNS_URL not set")
	}
	zone := "e2e.test"

	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AcceptTOS = true
	cfg.Email = "admin@e2e.test"
	cfg.CA = CACustom
	cfg.CustomDirectory = dir
	// the apex and its wildcard share one _acme-challenge name (two TXT values)
	cfg.Domains = []string{zone, "*." + zone, "backup." + zone}
	cfg.PowerDNS = PowerDNS{URL: pdnsURL, APIKey: "testkey", ServerID: "localhost", TTL: 1, PropagationSeconds: 1, DNSServer: dns}

	checks, err := m.CheckDNS(context.Background(), cfg)
	if err != nil {
		t.Fatalf("CheckDNS: %v", err)
	}
	for _, c := range checks {
		if c.Error != "" || c.Zone != zone {
			t.Fatalf("CheckDNS result: %+v", checks)
		}
	}

	if err := m.SetConfig(cfg); err != nil { // enabled -> starts issuing in the background
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		st := m.Status()
		if !st.Running && st.LastRun != nil {
			if !st.LastRun.OK {
				t.Fatalf("issuing failed: %s\n%s", st.LastRun.Error, strings.Join(st.LastRun.Log, "\n"))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for the certificate")
		}
		time.Sleep(time.Second)
	}
	st := m.Status()
	t.Logf("log:\n%s", strings.Join(st.LastRun.Log, "\n"))
	if !st.Active || st.Cert == nil || !sameDomains(st.Cert.Domains, cfg.Domains) {
		t.Fatalf("status after issuing: %+v", st)
	}
	if st.NeedsIssue != "" {
		t.Fatalf("fresh certificate still reported as due: %q", st.NeedsIssue)
	}

	// The challenge records must have been removed again.
	req, _ := http.NewRequest("GET", pdnsURL+"/api/v1/servers/localhost/zones/"+zone+".", nil)
	req.Header.Set("X-API-Key", "testkey")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var z struct {
		RRsets []struct{ Name, Type string } `json:"rrsets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&z); err != nil {
		t.Fatal(err)
	}
	for _, r := range z.RRsets {
		if strings.HasPrefix(r.Name, "_acme-challenge.") {
			t.Errorf("leftover challenge record %s %s", r.Name, r.Type)
		}
	}

	// A second manager (restart) finds the stored certificate and does not renew.
	m2, err := New(m.dir)
	if err != nil {
		t.Fatal(err)
	}
	m2.cfg = m.Config()
	if m2.Status().NeedsIssue != "" || !m2.Active() {
		t.Fatalf("restart: %+v", m2.Status())
	}
}
