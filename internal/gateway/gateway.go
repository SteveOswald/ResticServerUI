// Package gateway is the restic-facing reverse proxy. It authenticates
// clients with Basic-Auth against the user store, decides which repository a
// request targets, enforces the access mode and forwards allowed requests to
// rest-server (running with --private-repos --proxy-auth-username <header>),
// setting the header to the repository owner.
package gateway

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"restic-server-ui/internal/auth"
	"restic-server-ui/internal/store"
)

// MaxFolderDepth matches rest-server's handling of sub-repositories.
const MaxFolderDepth = 2

type ownerKey struct{}

type Gateway struct {
	store       *store.Store
	proxy       *httputil.ReverseProxy
	cache       *auth.CredCache
	limiter     *auth.Limiter
	logRequests bool
}

func New(st *store.Store, backend *url.URL, header string, limiter *auth.Limiter, logRequests bool) *Gateway {
	g := &Gateway{
		store:       st,
		cache:       auth.NewCredCache(5 * time.Minute),
		limiter:     limiter,
		logRequests: logRequests,
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization")
			// Always overwrite: never trust a client supplied value.
			pr.Out.Header.Set(header, pr.In.Context().Value(ownerKey{}).(string))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("gateway: backend error for %s %s: %v", r.Method, r.URL.Path, err)
			http.Error(w, "backend unavailable", http.StatusBadGateway)
		},
	}
	return g
}

// SplitPath mirrors rest-server's splitURLPath: up to MaxFolderDepth folder
// segments, stopping at the first object type name. ok is false for paths
// that must be rejected.
func SplitPath(p, rawPath string) (folder []string, rest string, ok bool) {
	if !strings.HasPrefix(p, "/") || rawPath != "" || strings.ContainsAny(p, "\\\x00") {
		// rawPath is only set if the path contained escapes that do not
		// round-trip (e.g. %2F) – restic never sends those.
		return nil, "", false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return nil, "", false
		}
	}
	parts := strings.SplitN(p, "/", MaxFolderDepth+2)
	for _, name := range parts[1 : len(parts)-1] {
		if store.ObjectTypes[name] {
			break
		}
		folder = append(folder, name)
	}
	for _, name := range folder {
		if !store.ValidSegment(name) {
			return nil, "", false
		}
	}
	if len(folder) == 0 {
		return nil, p, true
	}
	return folder, strings.TrimPrefix(p, "/"+strings.Join(folder, "/")), true
}

// MethodAllowed decides whether method on the repository-relative path rest
// is permitted in mode.
func MethodAllowed(mode store.Mode, method, rest string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	isLock := strings.HasPrefix(rest, "/locks/") && len(rest) > len("/locks/")
	switch mode {
	case store.ModeFull:
		return true
	case store.ModeAppendOnly:
		switch method {
		case http.MethodPost:
			return true // rest-server never overwrites existing objects
		case http.MethodDelete:
			return isLock
		}
	case store.ModeReadOnly:
		// restic needs to create and remove its lock even for reading
		return isLock && (method == http.MethodPost || method == http.MethodDelete)
	}
	return false
}

func (g *Gateway) authenticate(name, pass string) bool {
	u, ok := g.store.User(name)
	if !ok || u.Disabled {
		auth.DummyVerify(pass)
		return false
	}
	if g.cache.Check(name, pass, u.PasswordHash) {
		return true
	}
	if !auth.VerifyPassword(u.PasswordHash, pass) {
		return false
	}
	g.cache.Add(name, pass, u.PasswordHash)
	return true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restic"`)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	user := g.serve(rec, r)
	if g.logRequests {
		log.Printf("gateway: %s %s %s user=%q status=%d %s", auth.ClientIP(r), r.Method, r.URL.Path, user, rec.status, time.Since(start).Round(time.Millisecond))
	}
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) string {
	user, pass, ok := r.BasicAuth()
	if !ok {
		unauthorized(w)
		return ""
	}
	key := "gw|" + user + "|" + auth.ClientIP(r)
	if g.limiter.Blocked(key) {
		http.Error(w, "too many failed logins, try again later", http.StatusTooManyRequests)
		return user
	}
	if !g.authenticate(user, pass) {
		g.limiter.Fail(key)
		log.Printf("gateway: failed login for %q from %s", user, auth.ClientIP(r))
		unauthorized(w)
		return user
	}
	folder, rest, ok := SplitPath(r.URL.Path, r.URL.RawPath)
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return user
	}
	mode, ok := g.store.Access(user, folder)
	if !ok {
		log.Printf("gateway: denied %q access to %q", user, strings.Join(folder, "/"))
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return user
	}
	if !MethodAllowed(mode, r.Method, rest) {
		log.Printf("gateway: denied %q %s %s (mode %s)", user, r.Method, r.URL.Path, mode)
		http.Error(w, "operation not allowed ("+string(mode)+")", http.StatusForbidden)
		return user
	}
	ctx := context.WithValue(r.Context(), ownerKey{}, folder[0])
	g.proxy.ServeHTTP(w, r.WithContext(ctx))
	return user
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
