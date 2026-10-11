package build

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackageDeterministicAndSBOM(t *testing.T) {
	// Package requires a relative output; keep it outside both the source tree
	// and the input being hashed so a normal test cannot change release files.
	t.Chdir(t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	a, err := Package(root, "sbom.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Package(root, "sbom2.json")
	if err != nil {
		t.Fatal(err)
	}
	if a.ContentHash != b.ContentHash || a.FileCount != 1 {
		t.Fatalf("%+v %+v", a, b)
	}
}
