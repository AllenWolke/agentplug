package execution

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ValidateLiveLease binds current commands to their actual worker generation.
// 核对真实执行世代，防止旧执行者在同正文重新派发后重新获取公共能力。
func (m *Module) ValidateLiveLease(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) error {
	_, err := m.validatedLiveLease(ctx, scope, operation, bodyHash, policyHash)
	return err
}

func (m *Module) validatedLiveLease(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (platformruntime.Run, error) {
	run, err := m.validatedLiveCommand(ctx, scope, operation, bodyHash, policyHash)
	if err != nil {
		return platformruntime.Run{}, err
	}
	binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
	if !ok {
		return platformruntime.Run{}, errors.New("execution lease proof missing")
	}
	digest := sha256.Sum256([]byte(run.LeaseToken))
	if run.Revision != binding.Revision || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest[:])), []byte(binding.TokenHash)) != 1 {
		return platformruntime.Run{}, errors.New("execution lease proof denied")
	}
	return run, nil
}

func (m *Module) RenewCapabilityToken(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (string, error) {
	if m.dispatcher == nil || m.dispatcher.signer == nil || m.dispatcher.authorize == nil {
		return "", errors.New("execution renewal unavailable")
	}
	if err := m.ValidateLiveLease(ctx, scope, operation, bodyHash, policyHash); err != nil {
		return "", err
	}
	if err := m.dispatcher.authorize(ctx, scope); err != nil {
		return "", err
	}
	run, err := m.store.Get(scope.RunID)
	if err != nil {
		return "", err
	}
	var request contract.ExecuteRequest
	if contract.DecodeJSONPreservingNumbers(run.RequestJSON, &request) != nil {
		return "", errors.New("execution renewal contract unavailable")
	}
	if err := bindRunAuthorization(run, &request); err != nil {
		return "", err
	}
	request.ContextToken = ""
	request.Operation = operation
	if operation == "resume" {
		// Dispatch may wrap a durable reference as runtime recovery or group
		// continuation before hashing it. Rebuild that same ordered envelope,
		// including transient approval re-signing, before enforcing bodyHash.
		if err := m.dispatcher.prepareResumeRenewal(ctx, run, &request); err != nil {
			return "", err
		}
	} else if len(run.ResumeInputJSON) > 0 {
		if contract.DecodeJSONPreservingNumbers(run.ResumeInputJSON, &request.ResumeInput) != nil {
			return "", errors.New("execution resume contract unavailable")
		}
	}
	actualHash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil || actualHash != bodyHash {
		return "", errors.New("execution renewal digest denied")
	}
	// The old JWT is not an execution credential: current IAM/Run/lease were rechecked.
	// 旧 JWT 只证明原执行者身份；续签依赖当前 IAM、Run、会话与租约事实。
	return m.dispatcher.signer.Sign(ctx, scope, request)
}
