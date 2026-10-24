package modelgateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// PrepareContextCachePrefix preserves message order and tool transcripts. The
// caller must authorize live scope before preparation and again before send.
// The HMAC partition is stable across Runs, never an Agent-selected cache key.
func PrepareContextCachePrefix(scope sharedkernel.Scope, snapshot policyasset.Snapshot, messages []Message, secret []byte) ([]Message, string, error) {
	if snapshot.Model.ValidateContextCache() != nil {
		return nil, "", ErrModelUnavailable
	}
	if snapshot.Model.ContextCache == nil {
		return messages, "", nil
	}
	if scope.ValidateTrusted() != nil || scope.SessionID == "" || snapshot.Hash == "" || len(messages) == 0 || len(secret) < 16 {
		return nil, "", ErrModelUnavailable
	}
	// Scope includes the actor, installation, Agent version and authorization
	// epoch. Parent/Run/Trace are execution identity rather than cache identity.
	scope.RunID, scope.ParentRunID, scope.TraceID = "", "", ""
	encoded, err := json.Marshal(struct {
		Version string
		Scope   sharedkernel.Scope
		Policy  string
	}{"context-prefix/v1", scope, snapshot.Hash})
	if err != nil {
		return nil, "", ErrModelUnavailable
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(encoded)
	partition := hex.EncodeToString(mac.Sum(nil))
	marker := "Context partition [v1:" + partition + "].\n\n"
	out := append([]Message(nil), messages...)
	if out[0].Role == "system" {
		out[0].Content = marker + out[0].Content
	} else {
		out = append([]Message{{Role: "system", Content: marker}}, out...)
	}
	return out, partition, nil
}

// CacheUsage is a supplier measurement, not a platform predicted cache hit.
// Nil means unreported; a known zero is distinct from missing data.
type CacheUsage struct {
	CachedInputTokens   *int `json:"cached_input_tokens,omitempty"`
	UncachedInputTokens *int `json:"uncached_input_tokens,omitempty"`
}

func (u CacheUsage) Validate(total int) error {
	if total < 0 {
		return ErrProviderResponse
	}
	if u.CachedInputTokens == nil && u.UncachedInputTokens == nil {
		return nil
	}
	if u.CachedInputTokens == nil || u.UncachedInputTokens == nil || *u.CachedInputTokens < 0 || *u.CachedInputTokens > total || *u.UncachedInputTokens != total-*u.CachedInputTokens {
		return ErrProviderResponse
	}
	return nil
}

type providerCacheUsage struct {
	Hit     *int `json:"prompt_cache_hit_tokens"`
	Miss    *int `json:"prompt_cache_miss_tokens"`
	Details *struct {
		Cached *int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

func (u providerCacheUsage) normalize(total int) (CacheUsage, error) {
	hit := u.Hit
	if u.Details != nil && u.Details.Cached != nil {
		if hit != nil && *hit != *u.Details.Cached {
			return CacheUsage{}, ErrProviderResponse
		}
		hit = u.Details.Cached
	}
	if hit == nil && u.Miss == nil {
		return CacheUsage{}, nil
	}
	if hit == nil || *hit < 0 || *hit > total {
		return CacheUsage{}, ErrProviderResponse
	}
	miss := total - *hit
	if u.Miss != nil && *u.Miss != miss {
		return CacheUsage{}, ErrProviderResponse
	}
	value := *hit
	return CacheUsage{CachedInputTokens: &value, UncachedInputTokens: &miss}, nil
}
