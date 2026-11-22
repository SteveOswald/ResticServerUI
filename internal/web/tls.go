package web

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"restic-server-ui/internal/store"
	"restic-server-ui/internal/tlsmgr"
)

// tlsView is what the admin UI gets: the settings without the API key.
type tlsView struct {
	Config    tlsmgr.Config `json:"config"`
	APIKeySet bool          `json:"apiKeySet"`
	Status    tlsmgr.Status `json:"status"`
	// Ports of the HTTPS listeners, for the hints in the admin UI.
	UITLSPort      string `json:"uiTlsPort"`
	GatewayTLSPort string `json:"gatewayTlsPort"`
}

func (s *Server) tlsState() tlsView {
	cfg := s.cfg.TLS.Config()
	v := tlsView{APIKeySet: cfg.PowerDNS.APIKey != "", Status: s.cfg.TLS.Status(),
		UITLSPort: s.cfg.UITLSPort, GatewayTLSPort: s.cfg.GatewayTLSPort}
	cfg.PowerDNS.APIKey = ""
	v.Config = cfg
	return v
}

func (s *Server) writeTLSError(w http.ResponseWriter, err error) {
	var ve *tlsmgr.ValidationError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, ve.Msg)
	case errors.Is(err, tlsmgr.ErrBusy):
		writeError(w, http.StatusConflict, err.Error())
	default:
		log.Printf("web: tls error: %v", err)
		writeError(w, http.StatusBadGateway, err.Error())
	}
}

func (s *Server) tlsAvailable(w http.ResponseWriter) bool {
	if s.cfg.TLS == nil {
		writeError(w, http.StatusNotFound, "TLS-Verwaltung ist nicht verfügbar")
		return false
	}
	return true
}

func (s *Server) getTLS(w http.ResponseWriter, r *http.Request, _ store.User, _ string) {
	if !s.tlsAvailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.tlsState())
}

func (s *Server) putTLS(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	if !s.tlsAvailable(w) {
		return
	}
	var cfg tlsmgr.Config
	if !readJSON(w, r, &cfg) {
		return
	}
	if err := s.cfg.TLS.SetConfig(cfg); err != nil {
		s.writeTLSError(w, err)
		return
	}
	log.Printf("web: %s changed the TLS settings (enabled=%v)", admin.Name, cfg.Enabled)
	writeJSON(w, http.StatusOK, s.tlsState())
}

func (s *Server) issueTLS(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	if !s.tlsAvailable(w) {
		return
	}
	if err := s.cfg.TLS.Issue("manuell"); err != nil {
		s.writeTLSError(w, err)
		return
	}
	log.Printf("web: %s requested a certificate", admin.Name)
	writeJSON(w, http.StatusAccepted, s.tlsState())
}

func (s *Server) checkTLS(w http.ResponseWriter, r *http.Request, _ store.User, _ string) {
	if !s.tlsAvailable(w) {
		return
	}
	var cfg tlsmgr.Config
	if !readJSON(w, r, &cfg) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	res, err := s.cfg.TLS.CheckDNS(ctx, cfg)
	if err != nil {
		s.writeTLSError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": res})
}
