package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// RoutingMetadata comes from the approved, currently authorized catalog.
// Quality tier remains separately reviewed and bound to Evaluation evidence.
type RoutingMetadata struct {
	ResponseSchemaDialect string
	ContextCacheMode      string
	Selection             Selection
	Kind                  string
	ContextLimit          int
	SupportsFunctions     bool
	SupportsJSON          bool
	WireModel             string
	ReasoningDialect      string
}

type RoutingMetadataResolver interface {
	ResolveRoutingModel(context.Context, sharedkernel.Scope, string) (RoutingMetadata, error)
}

// CapabilitySHA256 excludes endpoints and current deployment lease IDs. It
// freezes capability requirements, not a credential or deployment address.
func (m RoutingMetadata) CapabilitySHA256() string {
	raw, _ := json.Marshal(struct {
		Version, Provider, ModelID, Model, Trust, Kind string
		Context                                        int
		Functions, JSON                                bool
		WireModel, ReasoningDialect                    string
		ContextCacheMode                               string `json:",omitempty"`
	}{m.Selection.ModelVersionID, m.Selection.ProviderID, m.Selection.ModelID,
		m.Selection.ModelKey, m.Selection.TrustZone, m.Kind, m.ContextLimit, m.SupportsFunctions, m.SupportsJSON, m.WireModel, m.ReasoningDialect, m.ContextCacheMode})
	if m.ResponseSchemaDialect != "" {
		raw, _ = json.Marshal(struct {
			Legacy                json.RawMessage
			ResponseSchemaDialect string
		}{raw, m.ResponseSchemaDialect})
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
