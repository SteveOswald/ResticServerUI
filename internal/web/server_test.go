package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"restic-server-ui/internal/auth"
	"restic-server-ui/internal/repos"
	"restic-server-ui/internal/store"
)

func TestAPIFlow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(store.User{Name: "admin", Role: store.RoleAdmin}, "admin-password"); err != nil {
		t.Fatal(err)
	}
	srv := New(Config{SessionTTL: time.Hour}, st, repos.NewScanner("", time.Minute), auth.NewLimiter(100, time.Minute))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	var cookie *http.Cookie
	call := func(method, path, body string, csrf bool) (int, map[string]any) {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if csrf {
			req.Header.Set("X-Requested-With", "rsui")
		}
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == cookieName {
				cookie = c
			}
		}
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	if code, _ := call("GET", "/api/users", "", true); code != 401 {
		t.Fatalf("unauthenticated list: %d", code)
	}
	if code, _ := call("POST", "/api/login", `{"username":"admin","password":"admin-password"}`, false); code != 403 {
		t.Fatalf("login without csrf header: %d", code)
	}
	if code, _ := call("POST", "/api/login", `{"username":"admin","password":"wrong"}`, true); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	if code, _ := call("POST", "/api/login", `{"username":"admin","password":"admin-password"}`, true); code != 200 {
		t.Fatalf("login: %d", code)
	}
	if code, m := call("POST", "/api/users", `{"name":"alice","password":"short"}`, true); code != 400 {
		t.Fatalf("short password: %d %v", code, m)
	}
	if code, m := call("POST", "/api/users", `{"name":"alice","password":"alice-password","mode":"append-only"}`, true); code != 201 {
		t.Fatalf("create alice: %d %v", code, m)
	}
	if code, _ := call("POST", "/api/users", `{"name":"ALICE","password":"alice-password"}`, true); code != 400 {
		t.Fatalf("duplicate (case-insensitive) user allowed: %d", code)
	}
	if code, _ := call("POST", "/api/users", `{"name":"bob","password":"bob-password"}`, true); code != 201 {
		t.Fatalf("create bob: %d", code)
	}
	if code, m := call("POST", "/api/shares", `{"path":"alice/laptop","grantee":"bob","mode":"full"}`, true); code != 201 {
		t.Fatalf("create share: %d %v", code, m)
	}
	if code, _ := call("POST", "/api/shares", `{"path":"alice/../x","grantee":"bob","mode":"full"}`, true); code != 400 {
		t.Fatalf("invalid share path accepted: %d", code)
	}
	if code, _ := call("PATCH", "/api/users/admin", `{"role":"user"}`, true); code != 400 {
		t.Fatalf("demoting last admin allowed: %d", code)
	}
	if code, _ := call("DELETE", "/api/users/admin", "", true); code != 400 {
		t.Fatalf("deleting last admin allowed: %d", code)
	}

	// bob logs in: sees own + shared grant (capped to alice's append-only), no admin API
	adminCookie := cookie
	cookie = nil
	if code, _ := call("POST", "/api/login", `{"username":"bob","password":"bob-password"}`, true); code != 200 {
		t.Fatalf("bob login: %d", code)
	}
	code, me := call("GET", "/api/me", "", false)
	if code != 200 {
		t.Fatalf("me: %d", code)
	}
	grants := me["grants"].([]any)
	if len(grants) != 2 || grants[1].(map[string]any)["mode"] != "append-only" {
		t.Fatalf("unexpected grants: %v", grants)
	}
	if code, _ := call("GET", "/api/users", "", false); code != 403 {
		t.Fatalf("non-admin listed users: %d", code)
	}

	// deleting alice removes the share
	cookie = adminCookie
	if code, _ := call("DELETE", "/api/users/alice", "", true); code != 200 {
		t.Fatalf("delete alice: %d", code)
	}
	if len(st.Shares()) != 0 {
		t.Fatalf("shares not cleaned up: %v", st.Shares())
	}
	// disabling bob kills his session
	if code, _ := call("PATCH", "/api/users/bob", `{"disabled":true}`, true); code != 200 {
		t.Fatalf("disable bob: %d", code)
	}
}
