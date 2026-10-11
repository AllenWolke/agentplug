package conversation

import (
	"strings"
	"testing"
)

func TestRejectedReviewCannotPublishAnswerInConversation(t *testing.T) {
	for _, output := range []map[string]any{
		{"status": "rejected", "approval_status": "rejected", "answer": "should-not-publish", "references": []any{"source"}, "grounding": map[string]any{"supported": true}},
		{"approval_status": "rejected", "answer": "should-not-publish", "references": []any{"source"}, "grounding": map[string]any{"supported": true}},
	} {
		content, metadata, err := projectRunResult(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(content, "should-not-publish") || metadata["answer"] != nil || metadata["references"] != nil || metadata["grounding"] != nil {
			t.Fatalf("rejected review leaked answer: content=%q metadata=%v", content, metadata)
		}
		if metadata["approval_status"] != "rejected" || metadata["status"] != "rejected" {
			t.Fatalf("review decision missing from history: %v", metadata)
		}
	}
}

func TestUnrelatedAgentStatusIsNotInventedAsHumanReview(t *testing.T) {
	content, metadata, err := projectRunResult(map[string]any{"status": "rejected", "answer": "domain-specific rejection"})
	if err != nil || content != "domain-specific rejection" || metadata["approval_status"] != nil {
		t.Fatalf("generic Agent status was rewritten as QA review: content=%q metadata=%v err=%v", content, metadata, err)
	}
}

func TestApprovedReviewKeepsAnswerAndDecision(t *testing.T) {
	content, metadata, err := projectRunResult(map[string]any{"status": "verified", "approval_status": "approved", "answer": "supported answer"})
	if err != nil || content != "supported answer" || metadata["approval_status"] != "approved" {
		t.Fatalf("approved answer projection: content=%q metadata=%v err=%v", content, metadata, err)
	}
}

func TestRequestChangesCannotPublishDraftAnswer(t *testing.T) {
	content, metadata, err := projectRunResult(map[string]any{"approval_status": "request_changes", "answer": "draft answer"})
	if err != nil || strings.Contains(content, "draft answer") || metadata["answer"] != nil || metadata["status"] != "waiting_review" {
		t.Fatalf("request-changes projection: content=%q metadata=%v err=%v", content, metadata, err)
	}
}
