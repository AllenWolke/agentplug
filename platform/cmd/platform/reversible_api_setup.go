package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/modelgateway"
)

func configureReversibleAPIRuntime(module *capability.Module, enabled, development bool, secrets modelgateway.SecretResolver) error {
	path := strings.TrimSpace(os.Getenv("PLATFORM_REVERSIBLE_API_BINDINGS_FILE"))
	if path == "" {
		return nil
	}
	if !enabled || module == nil {
		return errors.New("reversible API requires persistent cancellation owners")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("reversible API bindings unavailable")
	}
	body, readErr := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	f.Close()
	if readErr != nil || len(body) > 1<<20 {
		return errors.New("reversible API bindings unavailable")
	}
	var bindings []capability.ReversibleAPIBinding
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&bindings) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("reversible API bindings invalid")
	}
	var caPEM []byte
	if caFile := strings.TrimSpace(os.Getenv("PLATFORM_REVERSIBLE_API_CA_FILE")); caFile != "" {
		info, err := os.Lstat(caFile)
		if err != nil || !filepath.IsAbs(caFile) || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 256<<10 {
			return errors.New("reversible API CA unavailable")
		}
		caPEM, err = os.ReadFile(caFile)
		if err != nil {
			return errors.New("reversible API CA unavailable")
		}
	}
	provider, err := capability.NewReversibleAPIToolProvider(bindings, secrets, development, func(endpoint string, development bool) (*http.Client, error) {
		return newCodeControllerClient(endpoint, development, caPEM)
	})
	if err != nil || module.RegisterRuntimeExecutor(provider) != nil {
		return errors.New("reversible API registration unavailable")
	}
	return nil
}
