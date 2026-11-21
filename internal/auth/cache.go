package auth

import (
	"crypto/sha256"
	"net"
	"net/http"
	"sync"
	"time"
)

// CredCache remembers successful password verifications for a short time,
// because restic sends Basic-Auth with every single request and PBKDF2 is
// intentionally slow. The key includes the stored hash, so a password change
// invalidates the entry automatically.
type CredCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[[32]byte]time.Time
}

func NewCredCache(ttl time.Duration) *CredCache {
	return &CredCache{ttl: ttl, m: make(map[[32]byte]time.Time)}
}

func cacheKey(user, password, hash string) [32]byte {
	return sha256.Sum256([]byte(user + "\x00" + password + "\x00" + hash))
}

func (c *CredCache) Check(user, password, hash string) bool {
	k := cacheKey(user, password, hash)
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[k]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(c.m, k)
		return false
	}
	return true
}

func (c *CredCache) Add(user, password, hash string) {
	k := cacheKey(user, password, hash)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 10_000 {
		for key, exp := range c.m {
			if now.After(exp) {
				delete(c.m, key)
			}
		}
	}
	c.m[k] = now.Add(c.ttl)
}

// Limiter blocks a key after too many failed attempts within a window.
type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries map[string]*limitEntry
}

type limitEntry struct {
	count int
	first time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, entries: make(map[string]*limitEntry)}
}

func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false
	}
	if time.Since(e.first) > l.window {
		delete(l.entries, key)
		return false
	}
	return e.count >= l.max
}

func (l *Limiter) Fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 10_000 {
		for k, e := range l.entries {
			if now.Sub(e.first) > l.window {
				delete(l.entries, k)
			}
		}
	}
	e, ok := l.entries[key]
	if !ok || now.Sub(e.first) > l.window {
		l.entries[key] = &limitEntry{count: 1, first: now}
		return
	}
	e.count++
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// ClientIP returns the remote IP of a request (without port).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
