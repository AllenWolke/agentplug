package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticEntryDoesNotKeepPreviousDeployment(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "index.html")
	if err := os.WriteFile(entry, []byte(`<script src="/assets/old.js"></script>`), 0600); err != nil {
		t.Fatal(err)
	}
	g := &gateway{staticRoot: root}
	for _, path := range []string{"/", "/index.html", "/workspace/agent/example"} {
		response := httptest.NewRecorder()
		g.serveStatic(response, httptest.NewRequest(http.MethodGet, path, nil))
		status := http.StatusOK
		if path == "/index.html" {
			status = http.StatusMovedPermanently // net/http canonicalizes index.html to ./.
		}
		if response.Code != status || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("entry %s may cache a previous deployment: status=%d cache=%q", path, response.Code, response.Header().Get("Cache-Control"))
		}
	}
	if err := os.WriteFile(entry, []byte(`<script src="/assets/new.js"></script>`), 0600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	g.serveStatic(response, httptest.NewRequest(http.MethodGet, "/workspace", nil))
	if !strings.Contains(response.Body.String(), "new.js") {
		t.Fatal("entry must reflect the current deployment")
	}
	missing := httptest.NewRecorder()
	g.serveStatic(missing, httptest.NewRequest(http.MethodGet, "/assets/old.js", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatal("a removed bundle must never return entry HTML")
	}
}
