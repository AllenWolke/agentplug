package main

import (
	"context"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Only a durable execution owner can supply a renewal proof. Legacy ports retain
// exact epoch checks. A proof never replaces the fresh permission/lease checks.
func expectedExecutionEpoch(ctx context.Context, owner any, scope sharedkernel.Scope) (uint64, error) {
	if reader, ok := owner.(interface {
		ExpectedAuthorizationEpoch(context.Context, sharedkernel.Scope) (uint64, error)
	}); ok {
		return reader.ExpectedAuthorizationEpoch(ctx, scope)
	}
	return scope.AuthorizationEpoch, nil
}
