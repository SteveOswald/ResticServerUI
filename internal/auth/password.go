// Package auth contains password hashing, a credential cache and a simple
// brute-force limiter. It only uses the Go standard library.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

const (
	scheme      = "pbkdf2-sha256"
	iterations  = 600_000 // OWASP recommendation for PBKDF2-HMAC-SHA256
	saltLen     = 16
	keyLen      = 32
	MinPassword = 8
)

var b64 = base64.RawStdEncoding

// HashPassword returns an encoded PBKDF2-SHA256 hash:
// pbkdf2-sha256$<iterations>$<salt>$<key>
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", scheme, iterations, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != scheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err := b64.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := b64.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// DummyVerify burns roughly the same CPU time as a real verification so that
// unknown user names cannot be detected by timing.
func DummyVerify(password string) {
	dummyOnce.Do(func() { dummyHash, _ = HashPassword("dummy-password") })
	VerifyPassword(dummyHash, password)
}

// RandomPassword returns a random URL-safe password with n bytes of entropy.
func RandomPassword(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
