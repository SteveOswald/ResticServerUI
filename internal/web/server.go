// Package web serves the management UI and its JSON API.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"restic-server-ui/internal/auth"
	"restic-server-ui/internal/repos"
	"restic-server-ui/internal/store"
	"restic-server-ui/internal/tlsmgr"
)

//go:embed static
var staticFS embed.FS

const cookieName = "rsui_session"

type Config struct {
	PublicURL    string // URL of the restic gateway as seen by clients
	CookieSecure bool   // force the Secure flag (e.g. behind a TLS terminating proxy)
	SessionTTL   time.Duration
	Version      string
	GatewayPort  string          // port of the restic gateway, for the displayed URLs
	TLS          *tlsmgr.Manager // optional; enables the TLS settings API
}

type Server struct {
	cfg      Config
	store    *store.Store
	scanner  *repos.Scanner
	limiter  *auth.Limiter
	sessions *sessions
	handler  http.Handler
}

func New(cfg Config, st *store.Store, sc *repos.Scanner, limiter *auth.Limiter) *Server {
	s := &Server{cfg: cfg, store: st, scanner: sc, limiter: limiter, sessions: newSessions(cfg.SessionTTL)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.withUser(s.me))
	mux.HandleFunc("POST /api/me/password", s.withUser(s.changeOwnPassword))

	mux.HandleFunc("GET /api/users", s.withAdmin(s.listUsers))
	mux.HandleFunc("POST /api/users", s.withAdmin(s.createUser))
	mux.HandleFunc("PATCH /api/users/{name}", s.withAdmin(s.updateUser))
	mux.HandleFunc("POST /api/users/{name}/password", s.withAdmin(s.setUserPassword))
	mux.HandleFunc("DELETE /api/users/{name}", s.withAdmin(s.deleteUser))

	mux.HandleFunc("GET /api/shares", s.withAdmin(s.listShares))
	mux.HandleFunc("POST /api/shares", s.withAdmin(s.createShare))
	mux.HandleFunc("PATCH /api/shares/{id}", s.withAdmin(s.updateShare))
	mux.HandleFunc("DELETE /api/shares/{id}", s.withAdmin(s.deleteShare))

	mux.HandleFunc("GET /api/repos", s.withAdmin(s.listRepos))

	mux.HandleFunc("GET /api/tls", s.withAdmin(s.getTLS))
	mux.HandleFunc("PUT /api/tls", s.withAdmin(s.putTLS))
	mux.HandleFunc("POST /api/tls/issue", s.withAdmin(s.issueTLS))
	mux.HandleFunc("POST /api/tls/check", s.withAdmin(s.checkTLS))

	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServerFS(static))

	s.handler = securityHeaders(csrfCheck(mux))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// ---------------------------------------------------------------- middleware

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// csrfCheck requires a custom header on all state-changing API calls. Browsers
// cannot send it cross-origin without a CORS preflight, which we never allow.
func csrfCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Requested-With") != "rsui" {
				writeError(w, http.StatusForbidden, "CSRF-Prüfung fehlgeschlagen")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type ctxHandler func(w http.ResponseWriter, r *http.Request, u store.User, token string)

func (s *Server) currentUser(r *http.Request) (store.User, string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return store.User{}, "", false
	}
	name, ok := s.sessions.get(c.Value)
	if !ok {
		return store.User{}, "", false
	}
	u, ok := s.store.User(name)
	if !ok || u.Disabled {
		s.sessions.drop(c.Value)
		return store.User{}, "", false
	}
	return u, c.Value, true
}

func (s *Server) withUser(h ctxHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, tok, ok := s.currentUser(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "nicht angemeldet")
			return
		}
		h(w, r, u, tok)
	}
}

func (s *Server) withAdmin(h ctxHandler) http.HandlerFunc {
	return s.withUser(func(w http.ResponseWriter, r *http.Request, u store.User, tok string) {
		if u.Role != store.RoleAdmin {
			writeError(w, http.StatusForbidden, "nur für Administratoren")
			return
		}
		h(w, r, u, tok)
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeStoreError(w http.ResponseWriter, err error) {
	var ve *store.ValidationError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, ve.Msg)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "nicht gefunden")
	default:
		log.Printf("web: internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "interner Fehler (siehe Log)")
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "ungültige Anfrage")
		return false
	}
	return true
}

type userDTO struct {
	Name      string     `json:"name"`
	Role      store.Role `json:"role"`
	Disabled  bool       `json:"disabled"`
	Mode      store.Mode `json:"mode"`
	Note      string     `json:"note"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

func toDTO(u store.User) userDTO {
	return userDTO{Name: u.Name, Role: u.Role, Disabled: u.Disabled, Mode: u.OwnMode(), Note: u.Note, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}

// ---------------------------------------------------------------- session API

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.CookieSecure || r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) publicURL() string {
	if s.cfg.TLS == nil {
		return s.cfg.PublicURL
	}
	return s.cfg.TLS.AdjustPublicURL(s.cfg.PublicURL, s.cfg.GatewayPort)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	key := "ui|" + req.Username + "|" + auth.ClientIP(r)
	if s.limiter.Blocked(key) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Fehlversuche – bitte später erneut versuchen.")
		return
	}
	u, ok := s.store.User(req.Username)
	if !ok || u.Disabled {
		auth.DummyVerify(req.Password)
		ok = false
	} else {
		ok = auth.VerifyPassword(u.PasswordHash, req.Password)
	}
	if !ok {
		s.limiter.Fail(key)
		log.Printf("web: failed login for %q from %s", req.Username, auth.ClientIP(r))
		writeError(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch.")
		return
	}
	s.limiter.Reset(key)
	tok := s.sessions.create(u.Name)
	s.setCookie(w, r, tok, int(s.cfg.SessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sessions.drop(c.Value)
	}
	s.setCookie(w, r, "", -1)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, u store.User, _ string) {
	resp := map[string]any{
		"user":        toDTO(u),
		"publicUrl":   s.publicURL(),
		"version":     s.cfg.Version,
		"dataEnabled": s.scanner.Enabled(),
		"grants":      s.store.GrantsFor(u.Name),
	}
	if s.scanner.Enabled() {
		all, _, _ := s.scanner.Repos(false)
		grants := s.store.GrantsFor(u.Name)
		mine := []repos.Repo{}
		for _, rp := range all {
			for _, g := range grants {
				if rp.Path == g.Path || strings.HasPrefix(rp.Path, g.Path+"/") {
					mine = append(mine, rp)
					break
				}
			}
		}
		resp["repos"] = mine
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request, u store.User, tok string) {
	var req struct{ Current, New string }
	if !readJSON(w, r, &req) {
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Current) {
		writeError(w, http.StatusBadRequest, "Das aktuelle Passwort ist falsch.")
		return
	}
	if err := s.store.SetPassword(u.Name, req.New); err != nil {
		writeStoreError(w, err)
		return
	}
	s.sessions.dropUser(u.Name, tok)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- users API

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, _ store.User, _ string) {
	users := s.store.Users()
	out := make([]userDTO, 0, len(users))
	for _, u := range users {
		out = append(out, toDTO(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	var req struct {
		Name     string     `json:"name"`
		Password string     `json:"password"`
		Role     store.Role `json:"role"`
		Mode     store.Mode `json:"mode"`
		Note     string     `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	u, err := s.store.CreateUser(store.User{
		Name: strings.TrimSpace(req.Name), Role: req.Role, Mode: req.Mode, Note: strings.TrimSpace(req.Note),
	}, req.Password)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	log.Printf("web: %s created user %q (role %s, mode %s)", admin.Name, u.Name, u.Role, u.Mode)
	writeJSON(w, http.StatusCreated, toDTO(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	name := r.PathValue("name")
	var req struct {
		Role     *store.Role `json:"role"`
		Mode     *store.Mode `json:"mode"`
		Disabled *bool       `json:"disabled"`
		Note     *string     `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	u, err := s.store.UpdateUser(name, func(u *store.User) error {
		if req.Role != nil {
			u.Role = *req.Role
		}
		if req.Mode != nil {
			u.Mode = *req.Mode
		}
		if req.Disabled != nil {
			u.Disabled = *req.Disabled
		}
		if req.Note != nil {
			u.Note = strings.TrimSpace(*req.Note)
		}
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if u.Disabled {
		s.sessions.dropUser(u.Name, "")
	}
	log.Printf("web: %s updated user %q", admin.Name, u.Name)
	writeJSON(w, http.StatusOK, toDTO(u))
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request, admin store.User, tok string) {
	name := r.PathValue("name")
	var req struct{ Password string }
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.store.SetPassword(name, req.Password); err != nil {
		writeStoreError(w, err)
		return
	}
	keep := ""
	if name == admin.Name {
		keep = tok
	}
	s.sessions.dropUser(name, keep)
	log.Printf("web: %s set password of %q", admin.Name, name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	name := r.PathValue("name")
	if err := s.store.DeleteUser(name); err != nil {
		writeStoreError(w, err)
		return
	}
	s.sessions.dropUser(name, "")
	log.Printf("web: %s deleted user %q", admin.Name, name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- shares API

func (s *Server) listShares(w http.ResponseWriter, r *http.Request, _ store.User, _ string) {
	writeJSON(w, http.StatusOK, s.store.Shares())
}

func (s *Server) createShare(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	var req struct {
		Path    string     `json:"path"`
		Grantee string     `json:"grantee"`
		Mode    store.Mode `json:"mode"`
		Note    string     `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	sh, err := s.store.AddShare(store.Share{Path: req.Path, Grantee: req.Grantee, Mode: req.Mode, Note: strings.TrimSpace(req.Note)})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	log.Printf("web: %s shared %q with %q (%s)", admin.Name, sh.Path, sh.Grantee, sh.Mode)
	writeJSON(w, http.StatusCreated, sh)
}

func (s *Server) updateShare(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	var req struct {
		Mode store.Mode `json:"mode"`
		Note string     `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	sh, err := s.store.UpdateShare(r.PathValue("id"), req.Mode, strings.TrimSpace(req.Note))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	log.Printf("web: %s updated share %q → %q (%s)", admin.Name, sh.Path, sh.Grantee, sh.Mode)
	writeJSON(w, http.StatusOK, sh)
}

func (s *Server) deleteShare(w http.ResponseWriter, r *http.Request, admin store.User, _ string) {
	if err := s.store.DeleteShare(r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	log.Printf("web: %s removed share %s", admin.Name, r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- repos API

func (s *Server) listRepos(w http.ResponseWriter, r *http.Request, _ store.User, _ string) {
	if !s.scanner.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "repos": []any{}})
		return
	}
	list, scanned, err := s.scanner.Repos(r.URL.Query().Get("refresh") == "1")
	resp := map[string]any{"enabled": true, "repos": list, "scannedAt": scanned}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------- sessions

type sessionEntry struct {
	user    string
	expires time.Time
}

type sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]sessionEntry
}

func newSessions(ttl time.Duration) *sessions {
	return &sessions{ttl: ttl, m: make(map[string]sessionEntry)}
}

func (s *sessions) create(user string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, k)
		}
	}
	s.m[tok] = sessionEntry{user: user, expires: now.Add(s.ttl)}
	return tok
}

func (s *sessions) get(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[tok]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expires) {
		delete(s.m, tok)
		return "", false
	}
	return e.user, true
}

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// dropUser removes all sessions of user except the one with token keep.
func (s *sessions) dropUser(user, keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.m {
		if e.user == user && k != keep {
			delete(s.m, k)
		}
	}
}
