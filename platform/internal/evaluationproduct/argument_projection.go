package evaluationproduct

import "context"

type toolArgumentProjectionKey struct{}
type evidenceReadProfileKey struct{}

// The HTTP boundary validates the version. A larger bound grants no additional
// Run, principal or application access and is never inferred from Agent input.
func WithEvidenceReadProfile(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, evidenceReadProfileKey{}, version)
}

func EvidenceReadProfile(ctx context.Context) string {
	v, _ := ctx.Value(evidenceReadProfileKey{}).(string)
	return v
}

// WithToolArgumentProjection is set only by the authenticated public transport;
// it selects a redacted projection and grants no additional source access.
func WithToolArgumentProjection(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, toolArgumentProjectionKey{}, version)
}

func ToolArgumentProjection(ctx context.Context) string {
	v, _ := ctx.Value(toolArgumentProjectionKey{}).(string)
	return v
}
