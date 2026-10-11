package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunIsReadOnlyAndDetectsHTTP(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("from fastapi import FastAPI\napp=FastAPI()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Run(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Language != "python" || report.SuggestedAdapter != "legacy-http" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(root, "app.py")); err != nil {
		t.Fatal("inspector changed source")
	}
}
