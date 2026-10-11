package modelgateway

import (
	"context"
	"errors"
)

type embeddingPurposeKey struct{}

// Purpose is an encoding convention, never a model or credential override.
// Standard vendors may ignore the non-sensitive extension header. Governed
// multilingual providers use it for query instructions and passage prefixes.
func WithEmbeddingPurpose(ctx context.Context, purpose string) (context.Context, error) {
	if purpose != "" && purpose != "query" && purpose != "document" {
		return nil, errors.New("invalid embedding purpose")
	}
	return context.WithValue(ctx, embeddingPurposeKey{}, purpose), nil
}

func embeddingPurpose(ctx context.Context) string {
	value, _ := ctx.Value(embeddingPurposeKey{}).(string)
	return value
}
