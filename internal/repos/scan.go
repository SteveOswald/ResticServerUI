// Package repos scans the rest-server data directory (mounted read-only) to
// show repositories, sizes and the time of the latest snapshot.
package repos

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"restic-server-ui/internal/store"
)

type Repo struct {
	Path         string     `json:"path"`  // "alice" or "alice/laptop"
	Owner        string     `json:"owner"` // first path segment
	Size         int64      `json:"size"`
	Files        int        `json:"files"`
	Snapshots    int        `json:"snapshots"`
	Locks        int        `json:"locks"`
	LastSnapshot *time.Time `json:"lastSnapshot,omitempty"`
}

type Scanner struct {
	root string
	ttl  time.Duration

	mu      sync.Mutex
	scanned time.Time
	cached  []Repo
	lastErr error
}

func NewScanner(root string, ttl time.Duration) *Scanner {
	return &Scanner{root: root, ttl: ttl}
}

// Enabled reports whether the data directory is available.
func (s *Scanner) Enabled() bool {
	if s == nil || s.root == "" {
		return false
	}
	fi, err := os.Stat(s.root)
	return err == nil && fi.IsDir()
}

// Repos returns the cached scan result, rescanning when it is older than
// the TTL or when force is set.
func (s *Scanner) Repos(force bool) ([]Repo, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if force || s.cached == nil || time.Since(s.scanned) > s.ttl {
		s.cached, s.lastErr = scan(s.root)
		s.scanned = time.Now()
	}
	return s.cached, s.scanned, s.lastErr
}

func isRepo(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "config"))
	return err == nil && fi.Mode().IsRegular()
}

func scan(root string) ([]Repo, error) {
	out := []Repo{}
	top, err := os.ReadDir(root)
	if err != nil {
		return out, err
	}
	for _, d1 := range top {
		if !d1.IsDir() || strings.HasPrefix(d1.Name(), ".") {
			continue
		}
		dir1 := filepath.Join(root, d1.Name())
		if isRepo(dir1) {
			out = append(out, stat(dir1, d1.Name(), d1.Name()))
		}
		sub, err := os.ReadDir(dir1)
		if err != nil {
			continue
		}
		for _, d2 := range sub {
			if !d2.IsDir() || store.ObjectTypes[d2.Name()] || strings.HasPrefix(d2.Name(), ".") {
				continue
			}
			dir2 := filepath.Join(dir1, d2.Name())
			if isRepo(dir2) {
				out = append(out, stat(dir2, d1.Name()+"/"+d2.Name(), d1.Name()))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func stat(dir, path, owner string) Repo {
	r := Repo{Path: path, Owner: owner}
	if fi, err := os.Stat(filepath.Join(dir, "config")); err == nil {
		r.Size += fi.Size()
		r.Files++
	}
	for t := range store.ObjectTypes {
		if t == "config" {
			continue
		}
		_ = filepath.WalkDir(filepath.Join(dir, t), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			r.Size += fi.Size()
			r.Files++
			switch t {
			case "snapshots":
				r.Snapshots++
				mt := fi.ModTime().UTC()
				if r.LastSnapshot == nil || mt.After(*r.LastSnapshot) {
					r.LastSnapshot = &mt
				}
			case "locks":
				r.Locks++
			}
			return nil
		})
	}
	return r
}
