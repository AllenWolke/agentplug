package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var errIndexSecretUnavailable = errors.New("index workload credential unavailable")

type mountedIndexWorkloadSecrets struct{ Root string }

func (r mountedIndexWorkloadSecrets) validateRoot() error {
	if !filepath.IsAbs(r.Root) {
		return errIndexSecretUnavailable
	}
	info, err := os.Lstat(r.Root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errIndexSecretUnavailable
	}
	return nil
}

func indexWorkloadSecretName(scope sharedkernel.Scope) string {
	raw, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.InstallationID})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]) + ".json"
}

func (r mountedIndexWorkloadSecrets) Resolve(ctx context.Context, scope sharedkernel.Scope) (capability.TaskWorkloadCredential, error) {
	empty := capability.TaskWorkloadCredential{}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if scope.ValidateTrusted() != nil || !filepath.IsAbs(r.Root) {
		return empty, errIndexSecretUnavailable
	}
	root, err := os.Lstat(r.Root)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return empty, errIndexSecretUnavailable
	}
	path := filepath.Join(r.Root, indexWorkloadSecretName(scope))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return empty, errIndexSecretUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return empty, errIndexSecretUnavailable
	}
	defer file.Close()
	var wire struct {
		ClientID string `json:"client_id"`
		Secret   string `json:"client_secret"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 16385))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF {
		return empty, errIndexSecretUnavailable
	}
	for _, value := range []string{wire.ClientID, wire.Secret} {
		if len(value) == 0 || len(value) > 4096 || strings.TrimSpace(value) != value {
			return empty, errIndexSecretUnavailable
		}
		for _, char := range value {
			if char < 33 || char > 126 {
				return empty, errIndexSecretUnavailable
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return capability.TaskWorkloadCredential{ClientID: wire.ClientID, Secret: wire.Secret}, nil
}
