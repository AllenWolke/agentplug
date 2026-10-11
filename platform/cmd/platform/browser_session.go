package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func identityBrowserSessionCheck(store *identity.SQLStore) bootstrap.BrowserSessionCheck {
	return func(ctx context.Context, r *http.Request) (bool, error) {
		revision := uint64(0)
		if raw := r.Header.Get("X-Authentication-Revision"); raw != "" {
			var err error
			revision, err = strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return false, nil
			}
		}
		scope := sharedkernel.Scope{PrincipalType: r.Header.Get("X-Principal-Type"), PrincipalID: r.Header.Get("X-Principal-ID"), TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID")}
		err := store.ValidateBrowserSession(ctx, scope, r.Header.Get("X-Authentication-Session"), revision)
		if errors.Is(err, identity.ErrRefreshSessionRejected) {
			return false, nil
		}
		return err == nil, err
	}
}
