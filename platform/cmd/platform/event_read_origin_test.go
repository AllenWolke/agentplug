package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type eventOriginExecution struct {
	*execution.Module
	origin   sharedkernel.Scope
	proofErr error
}

func (e eventOriginExecution) ExpectedAuthorizationEpoch(_ context.Context, scope sharedkernel.Scope) (uint64, error) {
	if scope != e.origin {
		return 0, errors.New("foreign durable origin")
	}
	return 2, e.proofErr
}

func TestEventReadResolvesDurableOriginWithoutReplacingReadAuthority(t *testing.T) {
	for _, variant := range []string{"independent read epoch and trace", "revoked run", "revoked history", "stale run", "invalid proof", "foreign reader", "foreign parent", "foreign policy"} {
		t.Run(variant, func(t *testing.T) {
			ctx := context.Background()
			origin := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "installation", InstallationID: "installation", AgentID: "agent", AgentVersionID: "original-version", PrincipalType: "user", PrincipalID: "caller", SessionID: "session", RunID: "original-run", AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)}
			store := platformruntime.NewStore()
			_, err := store.Create(platformruntime.CreateRequest{ID: origin.RunID, Scope: origin, AgentVersionID: origin.AgentVersionID, IdempotencyKey: "original-key", Fingerprint: "original-body", AgentEndpoint: "http://original-agent:8080"})
			if err != nil {
				t.Fatal(err)
			}
			run, err := store.AcquireLease(origin.RunID, "lease", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			run, err = store.TransitionLeased(run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, run.Revision, "lease")
			if err != nil {
				t.Fatal(err)
			}
			hash := strings.Repeat("b", 64)
			if err := store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: run.ID, Revision: run.Revision, Operation: "run", BodyHash: strings.Repeat("c", 64), PolicyHash: hash}, "lease"); err != nil {
				t.Fatal(err)
			}
			module := execution.NewModuleWithRepository("internal", store)
			module.SetPinnedRunTargetResolver(func(_ context.Context, scope sharedkernel.Scope, endpoint string) error {
				if scope != origin || endpoint != "http://original-agent:8080" {
					return errors.New("foreign pinned origin")
				}
				return nil
			})
			e := eventOriginExecution{Module: module, origin: origin}
			iam := independentActionIAM{run: 2, history: 7}
			read := origin
			read.AuthorizationEpoch, read.TraceID = 7, strings.Repeat("d", 32)
			switch variant {
			case "revoked run":
				iam.deny = "run"
			case "revoked history":
				iam.deny = "history.read"
			case "stale run":
				iam.run = 3
			case "invalid proof":
				e.proofErr = errors.New("invalid proof")
			case "foreign reader":
				read.PrincipalID = "foreign"
			case "foreign parent":
				read.ParentRunID = "foreign-parent"
			case "foreign policy":
				hash = strings.Repeat("e", 64)
			}
			a := capabilityExecutionAuthority{execution: e, identity: iam, catalog: stopOnlyAuthorityCatalog{expected: origin}}
			err = a.AuthorizeEventRead(ctx, read, hash)
			if (err == nil) != (variant == "independent read epoch and trace") {
				t.Fatal("event origin/read boundary", err)
			}
			stored, err := store.Get(run.ID)
			if err != nil || stored.Scope != origin || stored.Revision != run.Revision || stored.LeaseToken != run.LeaseToken {
				t.Fatal("event read changed execution state", err)
			}
		})
	}
}
