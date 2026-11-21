package tlsmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// pdnsClient talks to the PowerDNS Authoritative Server HTTP API
// (https://doc.powerdns.com/authoritative/http-api/).
type pdnsClient struct {
	cfg PowerDNS
	hc  *http.Client
}

func newPDNS(cfg PowerDNS) *pdnsClient {
	return &pdnsClient{cfg: cfg, hc: &http.Client{Timeout: 20 * time.Second}}
}

type pdnsZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// fqdn returns name lower-cased with exactly one trailing dot.
func fqdn(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
}

func (c *pdnsClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := c.cfg.URL + "/api/v1/servers/" + url.PathEscape(c.cfg.ServerID) + path
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("PowerDNS nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			msg = "API-Key abgelehnt"
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return fmt.Errorf("PowerDNS-API %s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("PowerDNS-API: ungültige Antwort: %w", err)
		}
	}
	return nil
}

func (c *pdnsClient) ListZones(ctx context.Context) ([]pdnsZone, error) {
	var zones []pdnsZone
	if err := c.do(ctx, http.MethodGet, "/zones", nil, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

// pickZone returns the longest zone that contains name (label boundary).
func pickZone(zones []pdnsZone, name string) (pdnsZone, bool) {
	name = fqdn(name)
	var best pdnsZone
	found := false
	for _, z := range zones {
		zn := fqdn(z.Name)
		if name == zn || strings.HasSuffix(name, "."+zn) {
			if !found || len(zn) > len(fqdn(best.Name)) {
				best, found = z, true
			}
		}
	}
	return best, found
}

// FindZone resolves the zone that holds name: the configured zone, or the
// longest matching zone known to PowerDNS.
func (c *pdnsClient) FindZone(ctx context.Context, name string) (pdnsZone, error) {
	if c.cfg.Zone != "" {
		z := fqdn(c.cfg.Zone)
		if n := fqdn(name); n != z && !strings.HasSuffix(n, "."+z) {
			return pdnsZone{}, fmt.Errorf("%s liegt nicht in der konfigurierten Zone %s", strings.TrimSuffix(n, "."), strings.TrimSuffix(z, "."))
		}
		return pdnsZone{ID: z, Name: z}, nil
	}
	zones, err := c.ListZones(ctx)
	if err != nil {
		return pdnsZone{}, err
	}
	z, ok := pickZone(zones, name)
	if !ok {
		return pdnsZone{}, fmt.Errorf("keine passende Zone für %s in PowerDNS gefunden", strings.TrimSuffix(fqdn(name), "."))
	}
	return z, nil
}

type rrset struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        int      `json:"ttl,omitempty"`
	ChangeType string   `json:"changetype"`
	Records    []record `json:"records,omitempty"`
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

func (c *pdnsClient) patch(ctx context.Context, zone pdnsZone, sets ...rrset) error {
	return c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zone.ID), map[string]any{"rrsets": sets}, nil)
}

// SetTXT replaces the TXT RRset name with the given values.
func (c *pdnsClient) SetTXT(ctx context.Context, zone pdnsZone, name string, values []string) error {
	recs := make([]record, 0, len(values))
	for _, v := range values {
		recs = append(recs, record{Content: `"` + v + `"`})
	}
	return c.patch(ctx, zone, rrset{Name: fqdn(name), Type: "TXT", TTL: c.cfg.TTL, ChangeType: "REPLACE", Records: recs})
}

// DeleteTXT removes the TXT RRset name.
func (c *pdnsClient) DeleteTXT(ctx context.Context, zone pdnsZone, name string) error {
	return c.patch(ctx, zone, rrset{Name: fqdn(name), Type: "TXT", ChangeType: "DELETE"})
}
