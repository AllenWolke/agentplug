package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	protocol "github.com/lexagent/code-runtime-contract"
	"github.com/lexagent/platform/internal/capability"
)

func configureCodeRuntime(module *capability.Module, persistent bool, development bool, contextPublic ed25519.PublicKey) error {
	bindingsFile := strings.TrimSpace(os.Getenv("PLATFORM_CODE_BINDINGS_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("PLATFORM_CODE_PERMIT_PRIVATE_KEY_FILE"))
	caFile := strings.TrimSpace(os.Getenv("PLATFORM_CODE_CONTROLLER_CA_FILE"))
	if bindingsFile == "" && keyFile == "" && caFile == "" {
		return nil
	}
	if bindingsFile == "" || keyFile == "" || !persistent || module == nil || strings.TrimSpace(os.Getenv("PLATFORM_TOOL_CONFIRMATION_PRIVATE_KEY_FILE")) == "" {
		return errors.New("code runtime requires persistent IAM and human approval configuration")
	}
	file, err := os.Open(bindingsFile)
	if err != nil {
		return errors.New("code bindings unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(body) > 1<<20 {
		return errors.New("code bindings unavailable")
	}
	var bindings []capability.CodeBinding
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&bindings) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("code bindings invalid")
	}
	key, err := readToolApprovalKey(keyFile)
	if err != nil {
		return errors.New("code signing key unavailable")
	}
	defer clear(key)
	signer, err := protocol.NewSigner(ed25519.PrivateKey(key))
	if err != nil {
		return errors.New("code signing key invalid")
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	approvalKey, err := readToolApprovalKey(strings.TrimSpace(os.Getenv("PLATFORM_TOOL_CONFIRMATION_PRIVATE_KEY_FILE")))
	if err != nil {
		return errors.New("code approval boundary unavailable")
	}
	defer clear(approvalKey)
	if len(approvalKey) != ed25519.PrivateKeySize || bytes.Equal(public, contextPublic) || bytes.Equal(public, ed25519.PrivateKey(approvalKey).Public().(ed25519.PublicKey)) {
		return errors.New("code execution must use an independent signing key")
	}
	var caPEM []byte
	if caFile != "" {
		info, err := os.Lstat(caFile)
		if err != nil || !filepath.IsAbs(caFile) || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 256<<10 {
			return errors.New("code controller CA unavailable")
		}
		caPEM, err = os.ReadFile(caFile)
		if err != nil || len(caPEM) > 256<<10 {
			return errors.New("code controller CA unavailable")
		}
	}
	provider, err := capability.NewCodeToolProvider(bindings, signer, development,
		func(endpoint string, development bool) (*http.Client, error) {
			return newCodeControllerClient(endpoint, development, caPEM)
		})
	if err != nil {
		return errors.New("code provider configuration invalid")
	}
	if module.SetCodeToolProvider(provider) != nil {
		return errors.New("code runtime registration invalid")
	}
	return nil
}
