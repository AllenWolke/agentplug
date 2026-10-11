package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
)

func TestAgentEventTransportRejectsUnsafeSequence(t *testing.T) {
	for _, sequence := range []uint64{contract.MaxAgentEventSequence, contract.MaxAgentEventSequence + 1} {
		event := contract.ExecutionEvent{RunID: "run", Seq: sequence, EventType: "started", OccurredAt: time.Now().UTC(), Payload: map[string]any{}}
		proto, err := toProtoExecutionEvent(event)
		if sequence > contract.MaxAgentEventSequence {
			if !errors.Is(err, ErrGRPCEventProtocol) || proto != nil {
				t.Fatal("unsafe gRPC output sequence was accepted")
			}
		} else if err != nil {
			t.Fatal("safe gRPC boundary rejected")
		} else if _, err := fromProtoExecutionEvent(proto); err != nil {
			t.Fatal("safe gRPC boundary could not be read")
		}
		frame := fmt.Sprintf("id: %d\nevent: started\ndata: {\"run_id\":\"run\",\"seq\":%d,\"event_type\":\"started\",\"occurred_at\":\"2026-10-05T00:00:00Z\",\"payload\":{}}\n\n", sequence, sequence)
		events, failures := make(chan contract.ExecutionEvent, 1), make(chan error, 1)
		parseHTTPEventStream(context.Background(), io.NopCloser(strings.NewReader(frame)), "run", 4096, events, failures)
		failure := <-failures
		if sequence > contract.MaxAgentEventSequence {
			if !errors.Is(failure, ErrHTTPEventProtocol) || len(events) != 0 {
				t.Fatal("unsafe HTTP event was disclosed")
			}
		} else if failure != nil || len(events) != 1 {
			t.Fatal("safe HTTP boundary rejected")
		}
	}
}
