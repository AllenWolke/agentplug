package template

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndVerify(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "registry"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "registry", "index.yaml"), []byte("templates: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	r, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(); err != nil {
		t.Fatal(err)
	}
}
