// Package conformance pins the repository-level adapter conformance fixture: a
// legacy HTTP Agent must be onboarded with a mapping document and no code
// change, using exactly the packages the runtime ships.
// Package conformance 固定仓库级 Adapter 一致性夹具：存量 HTTP Agent 必须仅凭一份
// 映射文档、无需改代码即可接入，且使用运行时真正出货的那些包。
package conformance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lexagent/legacy-http-adapter/internal/descriptor"
	"github.com/lexagent/legacy-http-adapter/internal/mapping"
	"github.com/lexagent/legacy-http-adapter/internal/planloader"
)

// fixtureRelative walks from this package to the repository fixture. The path is
// asserted, not merely joined, so a moved fixture fails loudly instead of
// silently skipping the conformance case.
// fixtureRelative 从本包走到仓库夹具。该路径会被断言而非仅仅拼接，使夹具被移动时
// 显式失败，而不是静默跳过一致性用例。
const fixtureRelative = "../../../../conformance/adapter/legacy-http"

func fixtureDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(fixtureRelative)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"descriptor.json", "plan.json", "README.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("adapter conformance fixture is incomplete: %v", err)
		}
	}
	return dir
}

func TestLegacyAgentIsOnboardedByMappingOnly(t *testing.T) {
	dir := fixtureDir(t)
	d, err := descriptor.Load(filepath.Join(dir, "descriptor.json"))
	if err != nil {
		t.Fatalf("conformance descriptor was rejected: %v", err)
	}
	// The descriptor, not the environment, owns the upstream address and the
	// pinned plan; the events capability is legitimate only because a path is
	// registered for it.
	if d.Endpoint == "" || d.Path != "/api/ask" || d.MappingHash == "" || d.PlanPath == "" {
		t.Fatalf("descriptor did not carry the authoritative routing: %+v", d)
	}
	if d.EventsPath != "/api/ask/events" {
		t.Fatalf("descriptor did not register the events path: %+v", d)
	}
	declared := map[string]bool{}
	for _, capability := range d.Capabilities {
		declared[capability] = true
	}
	if !declared["invoke"] || !declared["events"] {
		t.Fatalf("descriptor capabilities were not preserved: %v", d.Capabilities)
	}

	loader := &planloader.Loader{
		Path:         filepath.Join(dir, filepath.FromSlash(d.PlanPath)),
		ExpectedHash: d.MappingHash,
		MinRevision:  uint64(d.Revision),
	}
	plan, err := loader.Refresh()
	if err != nil {
		t.Fatalf("the registered plan was rejected: %v", err)
	}
	if plan.Hash != d.MappingHash || plan.Revision != uint64(d.Revision) || plan.MappingID != "legacy-ask" {
		t.Fatalf("the loaded plan does not match the descriptor pin: %+v", plan)
	}
	if loader.Degraded() {
		t.Fatal("a clean conformance load must not be degraded")
	}

	// The mapping alone produces the upstream request ...
	legacyRequest, err := mapping.Apply(plan.Request, map[string]any{"question": "What is 2+2?"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacyRequest["question"] != "What is 2+2?" || len(legacyRequest) != 1 {
		t.Fatalf("request mapping was not applied from the fixture plan: %v", legacyRequest)
	}

	// ... and the platform response, with the declared constant included.
	platformResponse, err := mapping.Apply(plan.Response, nil, nil, map[string]any{"answer": "4"})
	if err != nil {
		t.Fatal(err)
	}
	if platformResponse["answer"] != "4" || platformResponse["model"] != "legacy-ask" {
		t.Fatalf("response mapping was not applied from the fixture plan: %v", platformResponse)
	}
}

func TestConformanceFixtureRejectsForeignAndStalePlans(t *testing.T) {
	dir := fixtureDir(t)
	d, err := descriptor.Load(filepath.Join(dir, "descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A foreign hash must not be accepted for this descriptor pin.
	foreign := &planloader.Loader{Path: filepath.Join(dir, filepath.FromSlash(d.PlanPath)), ExpectedHash: "sha256:some-other-plan"}
	if _, err := foreign.Refresh(); err == nil {
		t.Fatal("a plan whose hash does not match the descriptor pin was accepted")
	}
	// A minimum revision above the fixture revision must be refused, which is how
	// the platform stops a rolled-back plan from being served.
	stale := &planloader.Loader{Path: filepath.Join(dir, filepath.FromSlash(d.PlanPath)), ExpectedHash: d.MappingHash, MinRevision: uint64(d.Revision) + 1}
	if _, err := stale.Refresh(); err == nil {
		t.Fatal("a plan below the pinned minimum revision was accepted")
	}
}
