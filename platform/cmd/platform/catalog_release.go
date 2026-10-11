package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

func configureCatalogRelease(store *catalog.SQLStore, iam *identity.SQLStore, recorder audit.TxRecorder) {
	if store == nil || iam == nil || recorder == nil {
		return
	}
	store.SetReleasePorts(iam.AcquirePermissionReadContinuity,
		func(ctx context.Context, actor catalog.ControlActor, action catalog.ControlAction) error {
			scope := catalog.ControlScope{}
			if action == catalog.ControlSubmit {
				scope = catalog.ControlScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
			}
			err := (identityCatalogControl{store: iam}).AuthorizeCatalogControl(ctx, actor, action, scope)
			if err == nil || errors.Is(err, catalog.ErrCatalogForbidden) {
				return err
			}
			return catalog.ErrReleaseUnavailable
		},
		func(ctx context.Context, tx *sql.Tx, decision catalog.ReleaseDecision) error {
			id := fmt.Sprintf("catalog-release-%x", sha256.Sum256([]byte(decision.Kind+":"+decision.ID+":"+decision.Action)))
			a := decision.Actor
			return recorder.RecordTx(tx, audit.Event{ID: id, TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, ActorType: a.PrincipalType, ActorID: a.PrincipalID, TraceID: a.TraceID, AggregateType: "catalog_" + decision.Kind, AggregateID: decision.ID, Action: "catalog.release." + decision.Action, Outcome: "success", Summary: "Catalog release provenance and actor separation", CreatedAt: decision.CreatedAt})
		})
}
