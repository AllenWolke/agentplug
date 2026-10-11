package agentcoordination

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type stopPortsAdmitter struct{}

func (stopPortsAdmitter) AdmitChild(context.Context, *sql.Tx, ChildExecutionAdmission) (AdmittedChildExecution, error) {
	return AdmittedChildExecution{}, nil
}

type stopPortsObserverOnly struct{ stopPortsAdmitter }

func (stopPortsObserverOnly) ObserveChildLifecycle(context.Context, *sql.Tx, ChildExecutionRead) (ObservedChildLifecycle, error) {
	return ObservedChildLifecycle{}, nil
}

type stopPortsComplete struct{ stopPortsObserverOnly }

func (stopPortsComplete) CheckChildStopQuiescence(context.Context, sharedkernel.Scope) error {
	return nil
}

func TestDescendantStopLifecyclePortsRemainFailClosedForAdmittedChildren(t *testing.T) {
	tests := []struct {
		name     string
		children ChildExecutionAdmitter
		wantErr  bool
	}{
		{name: "no child admission wiring", children: nil, wantErr: true},
		{name: "admission without lifecycle observer", children: stopPortsAdmitter{}, wantErr: true},
		{name: "observer without stop barrier", children: stopPortsObserverOnly{}, wantErr: true},
		{name: "complete lifecycle ports", children: stopPortsComplete{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := descendantStopLifecyclePorts(test.children)
			if test.wantErr && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("missing admitted-child lifecycle port error = %v, want ErrUnavailable", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("complete admitted-child lifecycle ports rejected: %v", err)
			}
		})
	}
}
