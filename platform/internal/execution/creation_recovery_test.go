package execution

import (
	"context"
	"errors"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type recoveringCreationRecorder struct {
	conversationFail  bool
	taskFail          bool
	conversationCalls int
	taskCalls         int
	messageID         string
}

func (r *recoveringCreationRecorder) RecordRun(ctx context.Context, scope sharedkernel.Scope, body []byte) error {
	return r.RecordRunWithMessage(ctx, scope, body, "")
}
func (r *recoveringCreationRecorder) RecordRunWithMessage(_ context.Context, _ sharedkernel.Scope, _ []byte, id string) error {
	r.conversationCalls++
	r.messageID = id
	if r.conversationFail {
		return errors.New("conversation unavailable")
	}
	return nil
}
func (r *recoveringCreationRecorder) RecordRunTask(context.Context, sharedkernel.Scope) error {
	r.taskCalls++
	if r.taskFail {
		return errors.New("task unavailable")
	}
	return nil
}

func TestCreationReplayRepairsFailedConsumerAndRetainsOriginalMessage(t *testing.T) {
	for _, failedKind := range []string{"conversation", "task"} {
		t.Run(failedKind, func(t *testing.T) {
			store := platformruntime.NewStore()
			m := &Module{store: store}
			r := &recoveringCreationRecorder{conversationFail: failedKind == "conversation", taskFail: failedKind == "task"}
			m.SetConversationRecorder(r)
			m.SetTaskRecorder(r)
			scope := testScope("creation-recovery").domain()
			start := func(message string) {
				t.Helper()
				if _, err := m.StartRunWithMessage(context.Background(), scope, scope.RunID, "same-key", "same-body", "http://agent", []byte(`{"question":"scope-bound"}`), message); err != nil {
					t.Fatal(err)
				}
			}
			start("original-message")
			pending, _ := store.GetCreation(scope.RunID)
			if pending.ConversationPending != (failedKind == "conversation") || pending.TaskPending != (failedKind == "task") {
				t.Fatalf("acknowledged failed consumer: %+v", pending)
			}
			r.conversationFail, r.taskFail = false, false
			// A replay must use the first durable message, not a caller's replacement.
			// 重放使用首次持久化消息，不接纳调用方替换消息，也不重复成功消费者。
			start("tampered-replay-message")
			pending, _ = store.GetCreation(scope.RunID)
			if pending.ConversationPending || pending.TaskPending || r.messageID != "original-message" {
				t.Fatalf("lost replay repair: %+v message=%s", pending, r.messageID)
			}
			if failedKind == "conversation" && (r.conversationCalls != 2 || r.taskCalls != 1) {
				t.Fatal("replayed successful task")
			}
			if failedKind == "task" && (r.conversationCalls != 1 || r.taskCalls != 2) {
				t.Fatal("replayed successful conversation")
			}
			events, _ := store.Events(scope.RunID, 0)
			if len(events) != 1 {
				t.Fatalf("replay created another Run/event: %+v", events)
			}
		})
	}
}

func TestFreshDispatcherRepairsCreationWithoutRunExecution(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("created-before-crash").domain()
	if _, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: "v1", IdempotencyKey: "restart", Fingerprint: "fp", MessageID: "durable-message"}); err != nil {
		t.Fatal(err)
	}
	r := &recoveringCreationRecorder{}
	d := NewDispatcher(store, "", 1)
	d.conversation, d.taskRecorder = r, r
	d.reconcile(context.Background())
	pending, _ := store.PendingCreations(10)
	if len(pending) != 0 || r.conversationCalls != 1 || r.taskCalls != 1 || r.messageID != "durable-message" || len(d.queue) != 0 {
		t.Fatalf("creation was not repaired independently: %+v", pending)
	}
}
