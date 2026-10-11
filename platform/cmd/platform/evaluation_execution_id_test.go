package main

import "testing"

func TestEvaluationCasesHaveIndependentStableExecutionRuns(t *testing.T) {
	a := evaluationExecutionRunID("parent", 0)
	if a != evaluationExecutionRunID("parent", 0) || a == evaluationExecutionRunID("parent", 1) || a == evaluationExecutionRunID("other", 0) || len(a) > 128 {
		t.Fatal("evaluation cases share or lose stable execution identity")
	}
}
