// Package store persists users and shares in a single JSON file.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"restic-server-ui/internal/auth"
)

// Mode is the access level for a repository.
type Mode string

const (
	ModeReadOnly   Mode = "read-only"   // read + create/remove locks
	ModeAppendOnly Mode = "append-only" // read + add new data, no deletes (except locks)
	ModeFull       Mode = "full"        // everything incl. forget/prune
)

func (m Mode) Valid() bool { return m.rank() > 0 }

func (m Mode) rank() int {
	switch m {
	case ModeReadOnly:
		return 1
	case ModeAppendOnly:
		return 2
	case ModeFull:
		return 3
	}
	return 0
}

// MinMode returns the more restrictive of two modes.
func MinMode(a, b Mode) Mode {
	if a.rank() <= b.rank() {
		return a
	}
	return b
}

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

func (r Role) Valid() bool { return r == RoleAdmin || r == RoleUser }

type User struct {
	Name         string    `json:"name"`
	PasswordHash string    `json:"passwordHash"`
	Role         Role      `json:"role"`
	Disabled     bool      `json:"disabled"`
	Mode         Mode      `json:"mode"` // access mode for the user's own repositories
	Note         string    `json:"note,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// OwnMode is the effective access mode for the user's own repositories.
func (u User) OwnMode() Mode {
	if u.Mode.Valid() {
		return u.Mode
	}
	return ModeFull
}

// Share grants Grantee access to the repository (or all repositories) at Path.
// Path is "<owner>" (all repositories of owner) or "<owner>/<repo>".
type Share struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Grantee   string    `json:"grantee"`
	Mode      Mode      `json:"mode"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s Share) Owner() string {
	owner, _, _ := strings.Cut(s.Path, "/")
	return owner
}

// ValidationError is returned for invalid input; its message is user facing.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

var (
	ErrNotFound = errors.New("nicht gefunden")
)

// ObjectTypes are the special names rest-server uses inside a repository.
var ObjectTypes = map[string]bool{
	"config": true, "data": true, "index": true, "keys": true, "locks": true, "snapshots": true,
}

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}$`)
	segmentRe = regexp.MustCompile(`^[\p{L}\p{N}@._-]{1,128}$`)
)

// ValidateUsername checks that a name is usable as rest-server user and as
// first path segment.
func ValidateUsername(name string) error {
	if !nameRe.MatchString(name) {
		return invalid("Ungültiger Benutzername: erlaubt sind 1–64 Zeichen aus A-Z, a-z, 0-9, @ . _ - (Beginn mit Buchstabe/Ziffer).")
	}
	if ObjectTypes[strings.ToLower(name)] || strings.EqualFold(name, "metrics") {
		return invalid("Der Benutzername %q ist reserviert.", name)
	}
	return nil
}

// ValidSegment reports whether s is a valid repository path segment.
func ValidSegment(s string) bool {
	return s != "." && s != ".." && segmentRe.MatchString(s) && !ObjectTypes[s]
}

// NormalizeRepoPath validates "<owner>" or "<owner>/<repo>" and returns it
// without surrounding slashes.
func NormalizeRepoPath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	segs := strings.Split(p, "/")
	if p == "" || len(segs) > 2 {
		return "", invalid("Pfad muss \"benutzer\" oder \"benutzer/repo\" sein.")
	}
	for _, s := range segs {
		if !ValidSegment(s) {
			return "", invalid("Ungültiger Pfadbestandteil %q.", s)
		}
	}
	return p, nil
}

func ValidatePassword(pw string) error {
	if len(pw) < auth.MinPassword {
		return invalid("Das Passwort muss mindestens %d Zeichen lang sein.", auth.MinPassword)
	}
	if len(pw) > 1024 {
		return invalid("Das Passwort ist zu lang.")
	}
	return nil
}

type fileData struct {
	Version int      `json:"version"`
	Users   []*User  `json:"users"`
	Shares  []*Share `json:"shares"`
}

// Store is safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	path   string
	users  map[string]*User
	shares []*Share
}

// Open loads the store from path, creating the file if it does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path, users: make(map[string]*User)}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	var d fileData
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, u := range d.Users {
		if u != nil {
			s.users[u.Name] = u
		}
	}
	for _, sh := range d.Shares {
		if sh != nil {
			s.shares = append(s.shares, sh)
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	d := fileData{Version: 1, Users: make([]*User, 0, len(s.users)), Shares: s.shares}
	for _, u := range s.users {
		d.Users = append(d.Users, u)
	}
	sort.Slice(d.Users, func(i, j int) bool { return d.Users[i].Name < d.Users[j].Name })
	if d.Shares == nil {
		d.Shares = []*Share{}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ---------------------------------------------------------------- users

func (s *Store) Users() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (s *Store) User(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	if !ok {
		return User{}, false
	}
	return *u, true
}

func (s *Store) activeAdminsExcept(name string) int {
	n := 0
	for _, u := range s.users {
		if u.Name != name && u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

// HasActiveAdmin reports whether at least one enabled admin exists.
func (s *Store) HasActiveAdmin() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeAdminsExcept("") > 0
}

// CreateUser validates and stores a new user.
func (s *Store) CreateUser(u User, password string) (User, error) {
	if err := ValidateUsername(u.Name); err != nil {
		return User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	if u.Role == "" {
		u.Role = RoleUser
	}
	if !u.Role.Valid() {
		return User{}, invalid("Ungültige Rolle.")
	}
	if u.Mode == "" {
		u.Mode = ModeFull
	}
	if !u.Mode.Valid() {
		return User{}, invalid("Ungültiger Zugriffsmodus.")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	u.PasswordHash = hash
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		if strings.EqualFold(existing.Name, u.Name) {
			return User{}, invalid("Ein Benutzer %q existiert bereits.", existing.Name)
		}
	}
	nu := u
	s.users[u.Name] = &nu
	if err := s.saveLocked(); err != nil {
		delete(s.users, u.Name)
		return User{}, err
	}
	return nu, nil
}

// UpdateUser applies fn to a copy of the user and stores the result.
// fn must not change Name or PasswordHash.
func (s *Store) UpdateUser(name string, fn func(*User) error) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	nu := *old
	if err := fn(&nu); err != nil {
		return User{}, err
	}
	nu.Name, nu.PasswordHash, nu.CreatedAt = old.Name, old.PasswordHash, old.CreatedAt
	if !nu.Role.Valid() {
		return User{}, invalid("Ungültige Rolle.")
	}
	if !nu.Mode.Valid() {
		return User{}, invalid("Ungültiger Zugriffsmodus.")
	}
	wasAdmin := old.Role == RoleAdmin && !old.Disabled
	isAdmin := nu.Role == RoleAdmin && !nu.Disabled
	if wasAdmin && !isAdmin && s.activeAdminsExcept(name) == 0 {
		return User{}, invalid("Der letzte aktive Administrator kann nicht deaktiviert oder herabgestuft werden.")
	}
	nu.UpdatedAt = time.Now().UTC()
	s.users[name] = &nu
	if err := s.saveLocked(); err != nil {
		s.users[name] = old
		return User{}, err
	}
	return nu, nil
}

func (s *Store) SetPassword(name, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[name]
	if !ok {
		return ErrNotFound
	}
	nu := *old
	nu.PasswordHash = hash
	nu.UpdatedAt = time.Now().UTC()
	s.users[name] = &nu
	if err := s.saveLocked(); err != nil {
		s.users[name] = old
		return err
	}
	return nil
}

// DeleteUser removes the user and every share owned by or granted to it.
// Repository data on disk is not touched.
func (s *Store) DeleteUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[name]
	if !ok {
		return ErrNotFound
	}
	if old.Role == RoleAdmin && !old.Disabled && s.activeAdminsExcept(name) == 0 {
		return invalid("Der letzte aktive Administrator kann nicht gelöscht werden.")
	}
	oldShares := s.shares
	kept := make([]*Share, 0, len(s.shares))
	for _, sh := range s.shares {
		if sh.Grantee != name && sh.Owner() != name {
			kept = append(kept, sh)
		}
	}
	delete(s.users, name)
	s.shares = kept
	if err := s.saveLocked(); err != nil {
		s.users[name] = old
		s.shares = oldShares
		return err
	}
	return nil
}

// ---------------------------------------------------------------- shares

func (s *Store) Shares() []Share {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Share, 0, len(s.shares))
	for _, sh := range s.shares {
		out = append(out, *sh)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Grantee < out[j].Grantee
	})
	return out
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Store) AddShare(sh Share) (Share, error) {
	p, err := NormalizeRepoPath(sh.Path)
	if err != nil {
		return Share{}, err
	}
	sh.Path = p
	if !sh.Mode.Valid() {
		return Share{}, invalid("Ungültiger Zugriffsmodus.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[sh.Owner()]; !ok {
		return Share{}, invalid("Besitzer %q existiert nicht.", sh.Owner())
	}
	if _, ok := s.users[sh.Grantee]; !ok {
		return Share{}, invalid("Empfänger %q existiert nicht.", sh.Grantee)
	}
	if sh.Grantee == sh.Owner() {
		return Share{}, invalid("Ein Benutzer hat auf seine eigenen Repositories bereits Zugriff.")
	}
	for _, ex := range s.shares {
		if ex.Path == sh.Path && ex.Grantee == sh.Grantee {
			return Share{}, invalid("Diese Freigabe existiert bereits – bitte bearbeiten.")
		}
	}
	sh.ID = newID()
	sh.CreatedAt = time.Now().UTC()
	ns := sh
	s.shares = append(s.shares, &ns)
	if err := s.saveLocked(); err != nil {
		s.shares = s.shares[:len(s.shares)-1]
		return Share{}, err
	}
	return ns, nil
}

func (s *Store) UpdateShare(id string, mode Mode, note string) (Share, error) {
	if !mode.Valid() {
		return Share{}, invalid("Ungültiger Zugriffsmodus.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sh := range s.shares {
		if sh.ID != id {
			continue
		}
		ns := *sh
		ns.Mode, ns.Note = mode, note
		s.shares[i] = &ns
		if err := s.saveLocked(); err != nil {
			s.shares[i] = sh
			return Share{}, err
		}
		return ns, nil
	}
	return Share{}, ErrNotFound
}

func (s *Store) DeleteShare(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sh := range s.shares {
		if sh.ID != id {
			continue
		}
		old := s.shares
		s.shares = append(append([]*Share{}, s.shares[:i]...), s.shares[i+1:]...)
		if err := s.saveLocked(); err != nil {
			s.shares = old
			return err
		}
		return nil
	}
	return ErrNotFound
}

// covers reports whether a share path covers the repository folder path.
func covers(sharePath string, folder []string) bool {
	segs := strings.Split(sharePath, "/")
	if len(segs) > len(folder) {
		return false
	}
	for i := range segs {
		if segs[i] != folder[i] {
			return false
		}
	}
	return true
}

// Grant describes one path a user can access.
type Grant struct {
	Path    string `json:"path"`
	Mode    Mode   `json:"mode"`
	Own     bool   `json:"own"`
	ShareID string `json:"shareId,omitempty"`
	Note    string `json:"note,omitempty"`
}

// GrantsFor lists the user's own repository root plus all shares granted to
// the user, with effective (owner-capped) modes.
func (s *Store) GrantsFor(username string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil
	}
	out := []Grant{{Path: u.Name, Mode: u.OwnMode(), Own: true}}
	for _, sh := range s.shares {
		if sh.Grantee != username {
			continue
		}
		owner, ok := s.users[sh.Owner()]
		if !ok {
			continue
		}
		out = append(out, Grant{Path: sh.Path, Mode: MinMode(sh.Mode, owner.OwnMode()), ShareID: sh.ID, Note: sh.Note})
	}
	sort.Slice(out[1:], func(i, j int) bool { return out[1+i].Path < out[1+j].Path })
	return out
}

// Access returns the effective access mode of username for the repository
// at folder (as split by rest-server, e.g. ["alice"] or ["alice","laptop"]).
func (s *Store) Access(username string, folder []string) (Mode, bool) {
	if len(folder) == 0 {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok || u.Disabled {
		return "", false
	}
	owner, ok := s.users[folder[0]]
	if !ok {
		return "", false
	}
	ownerMode := owner.OwnMode()
	if owner.Name == u.Name {
		return ownerMode, true
	}
	var best Mode
	for _, sh := range s.shares {
		if sh.Grantee != username || !covers(sh.Path, folder) {
			continue
		}
		if sh.Mode.rank() > best.rank() {
			best = sh.Mode
		}
	}
	if best == "" {
		return "", false
	}
	// A share can never grant more than the owner itself has (e.g. an
	// append-only owner stays protected against deletes via shares).
	return MinMode(best, ownerMode), true
}
