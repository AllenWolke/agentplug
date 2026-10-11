package builtin

import (
	"github.com/lexagent/metric-runner/contracts"
	"testing"
)

func TestExactSentenceGroundingIgnoresUnrelatedParagraphPolarity(t *testing.T) {
	evidence := "The source is stored in PostgreSQL; the index is not an independent source. If indexing fails, do not publish it. Never bypass access control."
	for _, scenario := range []struct {
		name, claim string
		grounded    bool
	}{
		{"supported complete sentence", "The source is stored in PostgreSQL; the index is not an independent source.", true},
		{"negation reversal", "The source is stored in PostgreSQL; the index is an independent source.", false},
		{"condition omitted", "Publish it.", false},
		{"invented second sentence", "The source is stored in PostgreSQL; the index is not an independent source. All users are authorized.", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			v, err := (LexicalEntailmentMetric{}).Entail(contracts.Citation{Content: evidence}, contracts.Claim{Text: scenario.claim})
			if err != nil || v.Grounded != scenario.grounded {
				t.Fatalf("verdict=%+v error=%v", v, err)
			}
		})
	}
}

func TestExactSentencesDoNotDiscardQualifiersOrMatchSubstrings(t *testing.T) {
	for _, scenario := range []struct{ evidence, claim string }{
		{"No refunds are allowed.", "Refunds are allowed."},
		{"Only approved users may retrieve documents.", "Users may retrieve documents."},
		{"If approved; refunds are allowed.", "Refunds are allowed."},
		{"平台规范源保存在PostgreSQL中；索引不是独立事实来源。失败任务不得发布。", "索引是独立事实来源。"},
	} {
		if exactEvidenceSentences(scenario.evidence, scenario.claim) {
			t.Fatal("qualifier or sentence boundary dropped")
		}
	}
	if !exactEvidenceSentences("平台规范源保存在PostgreSQL中；索引不是独立事实来源。失败任务不得发布。", "平台规范源保存在 PostgreSQL 中；索引不是独立事实来源。") {
		t.Fatal("formatting-only sentence difference rejected")
	}
}
