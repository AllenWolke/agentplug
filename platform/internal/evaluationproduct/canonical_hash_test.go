package evaluationproduct

import (
	"encoding/json"
	"testing"
)

func TestContentHashCanonicalizesObjectKeysInsideRawJSON(t *testing.T) {
	left := []json.RawMessage{json.RawMessage(`{"case_id":"c1","input":{"question":"q","knowledge_scope":"local"},"expected":{"answer":"a"}}`)}
	right := []json.RawMessage{json.RawMessage(`{"expected":{"answer":"a"},"input":{"knowledge_scope":"local","question":"q"},"case_id":"c1"}`)}

	leftHash, err := contentHash(left)
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := contentHash(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftHash != rightHash {
		t.Fatalf("semantically identical JSON objects must have the same durable content hash: %s != %s", leftHash, rightHash)
	}
}

func TestContentHashPreservesArrayOrderAndLargeIntegers(t *testing.T) {
	first := []json.RawMessage{json.RawMessage(`{"n":9007199254740993}`), json.RawMessage(`{"n":2}`)}
	reordered := []json.RawMessage{json.RawMessage(`{"n":2}`), json.RawMessage(`{"n":9007199254740993}`)}
	firstHash, err := contentHash(first)
	if err != nil {
		t.Fatal(err)
	}
	reorderedHash, err := contentHash(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == reorderedHash {
		t.Fatal("array order is meaningful and must remain part of the content hash")
	}
}
