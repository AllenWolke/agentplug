package knowledge

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestHybridConsensusWinsWithoutScoreScaleAssumptions(t *testing.T) {
	a := Chunk{ID: "a", DocumentID: "one", DocumentVersion: "v1", Text: "first"}
	b := Chunk{ID: "b", DocumentID: "two", DocumentVersion: "v1", Text: "second"}
	c := Chunk{ID: "c", DocumentID: "three", DocumentVersion: "v1", Text: "third"}
	result, err := FuseHybrid(context.Background(), []RankedChunk{{a, 1000000}, {b, 50000}}, []RankedChunk{{b, 0.9}, {c, 0.8}}, map[string]string{"one": "v1", "two": "v1", "three": "v1"}, 1, DefaultHybridConfig())
	if err != nil || len(result) != 1 || result[0].DocumentID != "two" || result[0].LexicalRank != 2 || result[0].VectorRank != 1 || math.Abs(result[0].Score-0.03252247488101534) > 1e-12 {
		t.Fatalf("RRF consensus or TopK incorrect: %v %v", result, err)
	}
}

func TestHybridFiltersDeniedAndStaleBeforeRanking(t *testing.T) {
	a := Chunk{ID: "a", DocumentID: "one", DocumentVersion: "v1", Text: "visible"}
	allowed := map[string]string{"one": "v1"}
	base := []RankedChunk{{a, 0.9}}
	want, err := FuseHybrid(context.Background(), base, base, allowed, 1, DefaultHybridConfig())
	if err != nil {
		t.Fatal(err)
	}
	noise := []RankedChunk{{Chunk{ID: "denied", DocumentID: "private", DocumentVersion: "v1", Text: "hidden"}, math.NaN()}, {Chunk{ID: "old", DocumentID: "one", DocumentVersion: "v0", Text: "old"}, 100}, {a, 0.9}}
	got, err := FuseHybrid(context.Background(), noise, noise, allowed, 1, DefaultHybridConfig())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("denied/stale candidate influenced rank: %v %v", got, err)
	}
}

func TestHybridRejectsConflictingCitationAndUnorderedInput(t *testing.T) {
	a := Chunk{ID: "a", DocumentID: "doc", DocumentVersion: "v1", Text: "original"}
	b := a
	b.Text = "different text with the same immutable identity"
	allowed := map[string]string{"doc": "v1"}
	if _, err := FuseHybrid(context.Background(), []RankedChunk{{a, 1}}, []RankedChunk{{b, 1}}, allowed, 1, DefaultHybridConfig()); !errors.Is(err, ErrInvalidHybrid) {
		t.Fatalf("conflicting citation accepted: %v", err)
	}
	b.ID = "b"
	if _, err := FuseHybrid(context.Background(), []RankedChunk{{a, 0.1}, {b, 0.9}}, nil, allowed, 1, DefaultHybridConfig()); !errors.Is(err, ErrInvalidHybrid) {
		t.Fatalf("unordered ranking accepted: %v", err)
	}
}

func TestHybridRejectsScoreOverflow(t *testing.T) {
	a := Chunk{ID: "a", DocumentID: "doc", DocumentVersion: "v1", Text: "text"}
	_, err := FuseHybrid(context.Background(), []RankedChunk{{a, 1}}, []RankedChunk{{a, 1}}, map[string]string{"doc": "v1"}, 1, HybridConfig{RankConstant: 0.01, LexicalWeight: math.MaxFloat64, VectorWeight: math.MaxFloat64})
	if !errors.Is(err, ErrInvalidHybrid) {
		t.Fatalf("non-finite fused score accepted: %v", err)
	}
}
