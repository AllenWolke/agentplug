package execution

import (
	"bytes"
	"log"
	"strings"
	"testing"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestQueueRejectionEscapesRunIdentity(t *testing.T) {
	var output bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()
	d := &Dispatcher{childQueues: []chan string{make(chan string, 1)}}
	d.Enqueue(platformruntime.Run{ID: "run\r\nFORGED_LOG", RequestJSON: []byte(`{"protocol_version":"wrong","scope":{"delegation_depth":5}}`)})
	line := strings.TrimSuffix(output.String(), "\n")
	if strings.ContainsAny(line, "\r\n") || !strings.Contains(line, `run_id="run\r\nFORGED_LOG"`) {
		t.Fatalf("unsafe queue rejection: %q", line)
	}
}
