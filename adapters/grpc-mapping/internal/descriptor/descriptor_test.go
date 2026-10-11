package descriptor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.json")
	_ = os.WriteFile(p, []byte(`{"adapter_id":"a","service":"svc","method":"Invoke","revision":1}`), 0600)
	if _, e := Load(p); e != nil {
		t.Fatal(e)
	}
}
