package capability

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
)

func TestKnowledgeRerankParallelismRespectsPublishedLocalCapacity(t *testing.T) {
	for _, tt := range []struct {
		trust    string
		capacity int64
		want     int
	}{
		{"local", 1, 1}, {"local", 2, 2}, {"local", 0, 1}, {"external", 0, 2}, {"private", 0, 2}, {"unknown", 99, 1},
	} {
		if got := knowledgeSelectionParallelism(modelgateway.Selection{TrustZone: tt.trust, CapacityUnits: tt.capacity}); got != tt.want {
			t.Fatal(tt, got)
		}
	}
	m, op, _, _ := routeInvocationFixture(t)
	r := httptest.NewRequest("POST", "/internal/knowledge/search", nil)
	if got, err := m.knowledgeModelParallelism(r, op)(context.Background()); err != nil || got != 1 {
		t.Fatal("automatic-capable route must remain conservative", got, err)
	}
	op.Policy.Model.Routing = nil
	if _, err := m.knowledgeModelParallelism(r, op)(context.Background()); err == nil {
		t.Fatal("unsigned knowledge request obtained model capacity metadata")
	}
}
