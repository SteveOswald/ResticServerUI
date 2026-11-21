package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"restic-server-ui/internal/auth"
	"restic-server-ui/internal/store"
)

func TestSplitPath(t *testing.T) {
	cases := []struct {
		path   string
		raw    string
		folder []string
		rest   string
		ok     bool
	}{
		{"/alice/", "", []string{"alice"}, "/", true},
		{"/alice/config", "", []string{"alice"}, "/config", true},
		{"/alice/data/abc", "", []string{"alice"}, "/data/abc", true},
		{"/alice/laptop/", "", []string{"alice", "laptop"}, "/", true},
		{"/alice/laptop/keys/x", "", []string{"alice", "laptop"}, "/keys/x", true},
		{"/alice/a/b/config", "", []string{"alice", "a"}, "/b/config", true},
		{"/alice", "", nil, "/alice", true},
		{"/", "", nil, "/", true},
		{"/alice//config", "", nil, "", false},
		{"/alice/../bob/", "", nil, "", false},
		{"/alice/data/../../bob/config", "", nil, "", false},
		{"/alice/./config", "", nil, "", false},
		{"/alice%2Fbob/", "/alice%2Fbob/", nil, "", false},
		{"alice/", "", nil, "", false},
	}
	for _, c := range cases {
		folder, rest, ok := SplitPath(c.path, c.raw)
		if ok != c.ok || (ok && (!reflect.DeepEqual(folder, c.folder) || rest != c.rest)) {
			t.Errorf("SplitPath(%q) = %v, %q, %v; want %v, %q, %v", c.path, folder, rest, ok, c.folder, c.rest, c.ok)
		}
	}
}

func TestMethodAllowed(t *testing.T) {
	type tc struct {
		mode   store.Mode
		method string
		rest   string
		want   bool
	}
	cases := []tc{
		{store.ModeReadOnly, "GET", "/data/x", true},
		{store.ModeReadOnly, "HEAD", "/config", true},
		{store.ModeReadOnly, "POST", "/locks/abc", true},
		{store.ModeReadOnly, "DELETE", "/locks/abc", true},
		{store.ModeReadOnly, "POST", "/data/abc", false},
		{store.ModeReadOnly, "POST", "/", false},
		{store.ModeReadOnly, "DELETE", "/snapshots/abc", false},
		{store.ModeReadOnly, "POST", "/locks/", false},
		{store.ModeAppendOnly, "POST", "/data/abc", true},
		{store.ModeAppendOnly, "POST", "/", true},
		{store.ModeAppendOnly, "DELETE", "/locks/abc", true},
		{store.ModeAppendOnly, "DELETE", "/data/abc", false},
		{store.ModeAppendOnly, "DELETE", "/config", false},
		{store.ModeAppendOnly, "PUT", "/data/abc", false},
		{store.ModeFull, "DELETE", "/data/abc", true},
		{"", "POST", "/data/abc", false},
	}
	for _, c := range cases {
		if got := MethodAllowed(c.mode, c.method, c.rest); got != c.want {
			t.Errorf("MethodAllowed(%s, %s, %s) = %v, want %v", c.mode, c.method, c.rest, got, c.want)
		}
	}
}

func TestGatewayEndToEnd(t *testing.T) {
	const header = "X-Restic-User"
	var gotOwner, gotAuth, gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOwner, gotAuth, gotPath = r.Header.Get(header), r.Header.Get("Authorization"), r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "db.json"))
	if err != nil {
		t.Fatal(err)
	}
	mustUser := func(name string, mode store.Mode) {
		if _, err := st.CreateUser(store.User{Name: name, Mode: mode}, "password-"+name); err != nil {
			t.Fatal(err)
		}
	}
	mustUser("alice", store.ModeFull)
	mustUser("bob", store.ModeFull)
	mustUser("carol", store.ModeAppendOnly)
	mustUser("dave", store.ModeFull)
	if _, err := st.AddShare(store.Share{Path: "alice/laptop", Grantee: "bob", Mode: store.ModeReadOnly}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddShare(store.Share{Path: "carol", Grantee: "bob", Mode: store.ModeFull}); err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse(backend.URL)
	gw := New(st, u, header, auth.NewLimiter(100, 60e9), false)

	do := func(user, pass, method, path string, extraHeader bool) int {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		if extraHeader {
			req.Header.Set(header, "alice")
		}
		gotOwner, gotAuth, gotPath = "", "", ""
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec.Code
	}

	steps := []struct {
		user, pass, method, path string
		spoof                    bool
		want                     int
		owner                    string
	}{
		{"", "", "GET", "/alice/config", false, 401, ""},
		{"alice", "wrong", "GET", "/alice/config", false, 401, ""},
		{"alice", "password-alice", "GET", "/alice/config", false, 200, "alice"},
		{"alice", "password-alice", "DELETE", "/alice/data/x", false, 200, "alice"},
		{"alice", "password-alice", "GET", "/bob/config", false, 403, ""},
		{"bob", "password-bob", "GET", "/alice/laptop/config", false, 200, "alice"},
		{"bob", "password-bob", "POST", "/alice/laptop/locks/abc", false, 200, "alice"},
		{"bob", "password-bob", "POST", "/alice/laptop/data/abc", false, 403, ""},
		{"bob", "password-bob", "GET", "/alice/config", false, 403, ""},
		{"bob", "password-bob", "GET", "/alice/other/config", false, 403, ""},
		{"bob", "password-bob", "GET", "/bob/config", true, 200, "bob"},
		// share is "full", but carol herself is append-only → capped
		{"bob", "password-bob", "POST", "/carol/data/abc", false, 200, "carol"},
		{"bob", "password-bob", "DELETE", "/carol/data/abc", false, 403, ""},
		{"carol", "password-carol", "DELETE", "/carol/snapshots/abc", false, 403, ""},
		{"dave", "password-dave", "GET", "/", false, 403, ""},
		{"dave", "password-dave", "GET", "/dave/../alice/config", false, 404, ""},
	}
	for _, s := range steps {
		code := do(s.user, s.pass, s.method, s.path, s.spoof)
		if code != s.want {
			t.Errorf("%s %s %s: got %d want %d", s.user, s.method, s.path, code, s.want)
			continue
		}
		if code == 200 {
			if gotOwner != s.owner {
				t.Errorf("%s %s %s: owner header %q want %q", s.user, s.method, s.path, gotOwner, s.owner)
			}
			if gotAuth != "" {
				t.Errorf("Authorization header leaked to backend")
			}
			if gotPath != s.path {
				t.Errorf("path rewritten: %q", gotPath)
			}
		}
	}

	// Disabling a user must take effect immediately, even with cached creds.
	if _, err := st.UpdateUser("alice", func(u *store.User) error { u.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if code := do("alice", "password-alice", "GET", "/alice/config", false); code != 401 {
		t.Errorf("disabled user: got %d", code)
	}
	// Password change invalidates cache.
	if err := st.SetPassword("bob", "new-password-bob"); err != nil {
		t.Fatal(err)
	}
	if code := do("bob", "password-bob", "GET", "/bob/config", false); code != 401 {
		t.Errorf("old password after change: got %d", code)
	}
}
