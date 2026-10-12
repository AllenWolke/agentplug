package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStaticFilesRejectEscapingPaths(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "public")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("private-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("public-entry"), 0600); err != nil {
		t.Fatal(err)
	}
	g := &gateway{staticRoot: root}
	for _, path := range []string{"/../secret.txt", "/assets/../../secret.txt", "/..\\secret.txt", "//secret.txt", "/C:/secret.txt", "/\\\\localhost\\share\\secret.txt", "/assets/secret.txt:stream", "/assets/\x00secret.txt"} {
		t.Run(url.PathEscape(path), func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.URL.Path = path
			w := httptest.NewRecorder()
			g.serveStatic(w, r)
			if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "private-sentinel") {
				t.Fatalf("escaping path returned status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}

func TestStaticFilesConfineSymlinksAndSPAFallback(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "public")
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(parent, "secret.txt")
	if err := os.WriteFile(secret, []byte("private-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("public-entry"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "assets", "leak.txt")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("Windows account cannot create symlinks; also run this test on Linux")
		}
		t.Fatalf("symlink boundary test needs filesystem symlink support: %v", err)
	}
	if err := os.Symlink(parent, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("index.html", filepath.Join(root, "entry.html")); err != nil {
		t.Fatal(err)
	}
	g := &gateway{staticRoot: root}
	for _, path := range []string{"/assets/leak.txt", "/outside/secret.txt"} {
		w := httptest.NewRecorder()
		g.serveStatic(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "private-sentinel") {
			t.Fatalf("symlink escaped root: %s status=%d body=%q", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	g.serveStatic(w, httptest.NewRequest(http.MethodGet, "/entry.html", nil))
	if w.Code != http.StatusOK || w.Body.String() != "public-entry" {
		t.Fatal("safe in-root link should remain usable")
	}
	if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	g.serveStatic(w, httptest.NewRequest(http.MethodGet, "/workspace", nil))
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "private-sentinel") {
		t.Fatal("SPA fallback escaped root")
	}
}
