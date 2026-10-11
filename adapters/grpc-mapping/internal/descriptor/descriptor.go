package descriptor

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type Descriptor struct {
	AdapterID   string `json:"adapter_id"`
	Service     string `json:"service"`
	Method      string `json:"method"`
	MappingHash string `json:"mapping_hash"`
	Revision    int64  `json:"revision"`
}

func Load(path string) (Descriptor, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Descriptor{}, e
	}
	var d Descriptor
	if json.Unmarshal(b, &d) != nil {
		return Descriptor{}, errors.New("invalid descriptor JSON")
	}
	if d.AdapterID == "" || d.Service == "" || d.Method == "" || strings.Contains(d.Method, "/") || d.Revision < 1 {
		return Descriptor{}, errors.New("invalid gRPC descriptor")
	}
	return d, nil
}
