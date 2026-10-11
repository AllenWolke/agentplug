package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func readToolApprovalKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("tool approval key unavailable")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 1025))
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	if err != nil || len(body) > 1024 {
		return nil, errors.New("tool approval key invalid")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, errors.New("tool approval key invalid")
	}
	return key, nil
}

func configureToolApprovalControl(module *capability.Module, store *capability.SQLToolApprovalStore, adapter toolApprovalAdapter, contextPublic ed25519.PublicKey) error {
	path := strings.TrimSpace(os.Getenv("PLATFORM_TOOL_CONFIRMATION_PRIVATE_KEY_FILE"))
	if path == "" {
		return nil
	}
	if module == nil || store == nil || adapter.identity == nil || adapter.runs == nil || adapter.policy == nil || len(contextPublic) != ed25519.PublicKeySize {
		return errors.New("persistent authenticated tool approval dependencies required")
	}
	key, err := readToolApprovalKey(path)
	if err != nil {
		return err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	signer, err := capability.NewToolApprovalSigner(ed25519.PrivateKey(key), store)
	if err != nil {
		return err
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if bytes.Equal(public, contextPublic) {
		return errors.New("tool approval must use a separate human signing key")
	}
	if path := strings.TrimSpace(os.Getenv("PLATFORM_TOOL_CONFIRMATION_PUBLIC_KEY_FILE")); path != "" {
		configured, err := readToolApprovalKey(path)
		if err != nil || !bytes.Equal(configured, public) {
			return errors.New("tool approval public and private key mismatch")
		}
	}
	verifier, err := capability.NewToolConfirmationVerifier(public)
	if err != nil {
		return err
	}
	adapter.tools = module
	store.SetAuthorizer(adapter.Authorize)
	module.SetToolConfirmationVerifier(verifier)
	module.SetToolApprovalControl(&capability.ToolApprovalControl{Store: store, Signer: signer, Resolve: adapter.Resolve, StepUp: adapter.StepUp, ResolvePending: adapter.ResolvePending,
		ResumeReplay: adapter.ResumeReplay,
		Resume: func(r *http.Request, scope sharedkernel.Scope, operation capability.ToolApprovalOperation, claims capability.ToolConfirmationClaims) (any, error) {
			return adapter.Resume(r, scope, operation, claims, store)
		},
	})
	if adapter.execution != nil {
		adapter.execution.SetApprovedResumeResolver(func(ctx context.Context, scope sharedkernel.Scope, raw json.RawMessage) (map[string]any, error) {
			return adapter.resolveApprovedDispatch(ctx, scope, raw, signer)
		})
		adapter.execution.SetApprovedResumeRenewalResolver(func(ctx context.Context, scope sharedkernel.Scope, raw json.RawMessage) (map[string]any, error) {
			return adapter.resolveApprovedRenewal(ctx, scope, raw, signer)
		})
	}
	return nil
}
