package tlsmgr

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// retryInterval is how long a switched listener waits before it tries to bind
// again after a failed attempt (e.g. the port was still in use).
var retryInterval = 5 * time.Second

// Changed returns a channel that is closed the next time the TLS state
// (active or not, certificate) changes. Fetch a new channel after each wake-up.
func (m *Manager) Changed() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.changed == nil {
		m.changed = make(chan struct{})
	}
	return m.changed
}

// notifyLocked wakes everyone waiting on Changed. m.mu must be held.
func (m *Manager) notifyLocked() {
	if m.changed != nil {
		close(m.changed)
		m.changed = nil
	}
}

// ListenPlain returns a listener for plain HTTP on addr. It is bound only
// while TLS is NOT active: as soon as a certificate is in use the port is
// released, and it is bound again when TLS is switched off.
func (m *Manager) ListenPlain(addr string) (net.Listener, error) {
	return m.listenSwitched(addr, false)
}

// ListenTLS returns a listener for HTTPS on addr. It is bound only while TLS
// is active (connection refused otherwise) and follows the certificate
// without a restart.
func (m *Manager) ListenTLS(addr string) (net.Listener, error) {
	return m.listenSwitched(addr, true)
}

func (m *Manager) listenSwitched(addr string, wantTLS bool) (net.Listener, error) {
	s := &switchListener{
		m: m, addr: addr, wantTLS: wantTLS, cfg: m.TLSConfig(),
		conns: make(chan net.Conn), done: make(chan struct{}),
	}
	if err := s.sync(); err != nil { // fail fast on startup (port in use, …)
		return nil, err
	}
	go s.loop()
	return s, nil
}

// switchListener binds its port only while the TLS state matches wantTLS.
type switchListener struct {
	m       *Manager
	addr    string
	wantTLS bool
	cfg     *tls.Config

	conns chan net.Conn
	done  chan struct{}
	once  sync.Once

	mu   sync.Mutex
	ln   net.Listener
	last net.Addr
}

func (s *switchListener) name() string {
	if s.wantTLS {
		return "https"
	}
	return "http"
}

// sync binds or releases the port according to the current TLS state.
func (s *switchListener) sync() error {
	want := s.m.Active() == s.wantTLS
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	default:
	}
	switch {
	case want && s.ln == nil:
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			return err
		}
		s.ln, s.last = ln, ln.Addr()
		log.Printf("tls: %s listener bound on %s", s.name(), ln.Addr())
		go s.pump(ln)
	case !want && s.ln != nil:
		s.ln.Close()
		s.ln = nil
		log.Printf("tls: %s listener on %s closed (tls active=%v)", s.name(), s.addr, !s.wantTLS)
	}
	return nil
}

func (s *switchListener) loop() {
	for {
		ch := s.m.Changed() // before sync, so no change gets lost
		var retry <-chan time.Time
		if err := s.sync(); err != nil {
			log.Printf("tls: %s listener on %s: %v (retrying)", s.name(), s.addr, err)
			retry = time.After(retryInterval)
		}
		select {
		case <-ch:
		case <-retry:
		case <-s.done:
			return
		}
	}
}

// pump moves accepted connections to Accept until ln is closed.
func (s *switchListener) pump(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // e.g. out of file descriptors
			continue
		}
		select {
		case s.conns <- c:
		case <-s.done:
			c.Close()
			return
		}
	}
}

func (s *switchListener) Accept() (net.Conn, error) {
	for {
		select {
		case c := <-s.conns:
			if s.m.Active() != s.wantTLS { // state flipped while the connection was queued
				c.Close()
				continue
			}
			if s.wantTLS {
				return tls.Server(c, s.cfg), nil
			}
			return c, nil
		case <-s.done:
			return nil, net.ErrClosed
		}
	}
}

func (s *switchListener) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		if s.ln != nil {
			s.ln.Close()
			s.ln = nil
		}
		s.mu.Unlock()
	})
	return nil
}

func (s *switchListener) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last != nil {
		return s.last
	}
	return &net.TCPAddr{}
}

// ---------------------------------------------------------------- handlers

// RedirectToHTTPS redirects every request to the HTTPS port while TLS is
// active (except /healthz, used by the container health check); otherwise it
// passes the request on to next.
func (m *Manager) RedirectToHTTPS(next http.Handler, tlsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.Active() || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		target := "https://" + joinHostPort(m.CertHost(host), tlsPort) + r.URL.RequestURI()
		// Temporary: a cached permanent redirect would lock browsers out
		// after TLS has been switched off again.
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
}

// DenyPlain refuses requests while TLS is active. The plain listener is
// released as soon as TLS becomes active; this covers keep-alive connections
// that were established before.
func (m *Manager) DenyPlain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Active() {
			w.Header().Set("Connection", "close")
			http.Error(w, "HTTP ist deaktiviert – bitte HTTPS verwenden.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// joinHostPort formats host[:port]; the port is omitted when empty or 443.
func joinHostPort(host, port string) string {
	if port == "" || port == "443" {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}
