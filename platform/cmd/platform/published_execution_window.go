package main

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func (a capabilityExecutionAuthority) PublishedExecutionWindow(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string, seconds int) (time.Time, time.Time, error) {
	reader, ok := a.execution.(interface {
		PublishedExecutionWindow(context.Context, sharedkernel.Scope, string, string, string, int) (time.Time, time.Time, error)
	})
	if !ok {
		return time.Time{}, time.Time{}, errors.New("published execution window unavailable")
	}
	return reader.PublishedExecutionWindow(ctx, scope, operation, bodyHash, policyHash, seconds)
}
