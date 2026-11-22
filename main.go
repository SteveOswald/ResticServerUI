// restic-server-ui: user management UI and access-control gateway for
// restic rest-server running in --private-repos mode.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // the distroless image has no zoneinfo; honour TZ

	"restic-server-ui/internal/auth"
	"restic-server-ui/internal/gateway"
	"restic-server-ui/internal/repos"
	"restic-server-ui/internal/store"
	"restic-server-ui/internal/tlsmgr"
	"restic-server-ui/internal/web"
)

var version = "dev"

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(env(key, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: %s [healthcheck|version]\n", os.Args[0])
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	uiAddr := env("UI_LISTEN", ":8080")
	gwAddr := env("GATEWAY_LISTEN", ":8000")
	uiTLSAddr := env("UI_TLS_LISTEN", ":8443")
	gwTLSAddr := env("GATEWAY_TLS_LISTEN", ":8444")
	configDir := env("CONFIG_DIR", "/config")
	dataDir := env("DATA_DIR", "/data")
	header := env("PROXY_AUTH_HEADER", "X-Restic-User")
	tlsCert, tlsKey := env("TLS_CERT", ""), env("TLS_KEY", "")

	backend, err := url.Parse(env("BACKEND_URL", "http://rest-server:8000"))
	if err != nil || backend.Scheme == "" || backend.Host == "" {
		return fmt.Errorf("invalid BACKEND_URL")
	}
	ttl, err := time.ParseDuration(env("SESSION_TTL", "12h"))
	if err != nil {
		return fmt.Errorf("invalid SESSION_TTL: %w", err)
	}

	st, err := store.Open(filepath.Join(configDir, "users.json"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	if err := bootstrapAdmin(st); err != nil {
		return err
	}

	// TLS: certificates come from Let's Encrypt (configured in the admin UI) or,
	// optionally, from fixed files given by TLS_CERT/TLS_KEY.
	tlsm, err := tlsmgr.New(configDir)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if (tlsCert == "") != (tlsKey == "") {
		return errors.New("TLS_CERT and TLS_KEY must be set together")
	}
	if tlsCert != "" {
		if err := tlsm.LoadStatic(tlsCert, tlsKey); err != nil {
			return fmt.Errorf("load TLS_CERT/TLS_KEY: %w", err)
		}
		log.Printf("tls: using fixed certificate from %s", tlsCert)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go tlsm.Run(ctx)

	limiter := auth.NewLimiter(10, 15*time.Minute)
	scanner := repos.NewScanner(dataDir, 2*time.Minute)
	if !scanner.Enabled() {
		log.Printf("data directory %q not available – repository statistics disabled", dataDir)
	}

	gw := gateway.New(st, backend, header, limiter, envBool("LOG_REQUESTS", false))
	ui := web.New(web.Config{
		PublicURL:      strings.TrimRight(env("PUBLIC_URL", ""), "/"),
		CookieSecure:   envBool("COOKIE_SECURE", false),
		SessionTTL:     ttl,
		Version:        version,
		GatewayPort:    portOf(gwAddr),
		GatewayTLSPort: portOf(gwTLSAddr),
		UITLSPort:      portOf(uiTLSAddr),
		TLS:            tlsm,
	}, st, scanner, limiter)

	// Separate ports for HTTP and HTTPS. The listeners follow the TLS state
	// at runtime, so enabling TLS in the admin UI needs no restart:
	//   - gateway, HTTP : bound only while TLS is NOT active (released afterwards)
	//   - gateway, HTTPS: bound only while TLS is active
	//   - web UI, HTTP  : always bound; redirects to HTTPS while TLS is active
	//   - web UI, HTTPS : bound only while TLS is active
	gwSrv := func() *http.Server {
		return &http.Server{ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 5 * time.Minute}
	}
	uiSrv := func() *http.Server {
		return &http.Server{ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute}
	}
	type listenerSpec struct {
		name   string
		addr   string
		listen func(string) (net.Listener, error)
		srv    *http.Server
		h      http.Handler
	}
	specs := []listenerSpec{
		{"restic gateway (http)", gwAddr, tlsm.ListenPlain, gwSrv(), tlsm.DenyPlain(gw)},
		{"restic gateway (https)", gwTLSAddr, tlsm.ListenTLS, gwSrv(), gw},
		{"web ui (http)", uiAddr, func(a string) (net.Listener, error) { return net.Listen("tcp", a) }, uiSrv(), tlsm.RedirectToHTTPS(ui, portOf(uiTLSAddr))},
		{"web ui (https)", uiTLSAddr, tlsm.ListenTLS, uiSrv(), ui},
	}
	var servers []*http.Server
	errc := make(chan error, len(specs))
	for _, sp := range specs {
		ln, err := sp.listen(sp.addr)
		if err != nil {
			return fmt.Errorf("%s: %w", sp.name, err)
		}
		sp.srv.Addr, sp.srv.Handler = sp.addr, sp.h
		servers = append(servers, sp.srv)
		log.Printf("%s configured on %s (tls active=%v)", sp.name, sp.addr, tlsm.Active())
		go func() {
			if err := sp.srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", sp.name, err)
			}
		}()
	}
	log.Printf("restic-server-ui %s started, backend %s, proxy header %s", version, backend, header)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case s := <-sig:
		log.Printf("received %s, shutting down", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
	return nil
}

// bootstrapAdmin creates the initial admin account if no active admin exists,
// and optionally resets its password (RESET_ADMIN_PASSWORD=true).
func bootstrapAdmin(st *store.Store) error {
	name := env("ADMIN_USERNAME", "admin")
	pw := env("ADMIN_PASSWORD", "")
	if envBool("RESET_ADMIN_PASSWORD", false) {
		if pw == "" {
			return errors.New("RESET_ADMIN_PASSWORD requires ADMIN_PASSWORD")
		}
		if _, ok := st.User(name); ok {
			if err := st.SetPassword(name, pw); err != nil {
				return fmt.Errorf("reset admin password: %w", err)
			}
			if _, err := st.UpdateUser(name, func(u *store.User) error {
				u.Role, u.Disabled = store.RoleAdmin, false
				return nil
			}); err != nil {
				return err
			}
			log.Printf("password of admin %q has been reset – remove RESET_ADMIN_PASSWORD now", name)
			return nil
		}
	}
	if st.HasActiveAdmin() {
		return nil
	}
	generated := false
	if pw == "" {
		pw = auth.RandomPassword(15)
		generated = true
	}
	if _, ok := st.User(name); ok {
		return fmt.Errorf("no active admin exists and user %q is not an admin; set RESET_ADMIN_PASSWORD=true and ADMIN_PASSWORD to recover", name)
	}
	if _, err := st.CreateUser(store.User{Name: name, Role: store.RoleAdmin, Mode: store.ModeFull, Note: "initialer Administrator"}, pw); err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	if generated {
		log.Printf("created initial admin %q with generated password: %s", name, pw)
	} else {
		log.Printf("created initial admin %q (password from ADMIN_PASSWORD)", name)
	}
	return nil
}

// portOf returns the port of a listen address like ":8000" or "0.0.0.0:8000".
func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return ""
}

// healthcheck asks the plain-HTTP UI port on localhost. That port is always
// bound, and /healthz is exempt from the redirect to HTTPS.
func healthcheck() int {
	addr := env("UI_LISTEN", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
