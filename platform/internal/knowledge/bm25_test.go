package knowledge

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestBM25KnownScoresAndTermSaturation(t *testing.T) {
	chunks := []Chunk{{ID: "a", DocumentID: "one", DocumentVersion: "v1", Text: "go go"}, {ID: "b", DocumentID: "two", DocumentVersion: "v1", Text: "go java"}}
	result, err := RankBM25(context.Background(), "GO", chunks, map[string]string{"one": "v1", "two": "v1"}, 2, DefaultBM25Config())
	if err != nil || len(result) != 2 {
		t.Fatalf("rank: %v %v", result, err)
	}
	// Hand-calculated two-passage corpus, equal passage lengths, df(go)=2.
	if math.Abs(result[0].Score-0.2506921405916876) > 1e-12 || math.Abs(result[1].Score-0.1823215567939546) > 1e-12 {
		t.Fatalf("not BM25 saturation: %+v", result)
	}
}

func TestDeniedAndStaleContentCannotAffectScoresOrTopK(t *testing.T) {
	allowed := map[string]string{"public": "current"}
	base := []Chunk{{ID: "one", DocumentID: "public", DocumentVersion: "current", Text: "database backup"}}
	want, err := RankBM25(context.Background(), "backup", base, allowed, 1, DefaultBM25Config())
	if err != nil {
		t.Fatal(err)
	}
	withDenied := append(append([]Chunk{}, base...), Chunk{ID: "denied", DocumentID: "private", DocumentVersion: "current", Text: string([]byte{0xff})}, Chunk{ID: "old", DocumentID: "public", DocumentVersion: "old", Text: "backup backup backup"})
	got, err := RankBM25(context.Background(), "backup", withDenied, allowed, 1, DefaultBM25Config())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("denied/stale corpus influenced ranking: %v %v", got, err)
	}
}

func TestChineseRetrievalAndNoMatch(t *testing.T) {
	chunks := []Chunk{{ID: "one", DocumentID: "doc", DocumentVersion: "v1", Text: "数据库备份与恢复操作"}}
	allowed := map[string]string{"doc": "v1"}
	result, err := RankBM25(context.Background(), "备份恢复", chunks, allowed, 1, DefaultBM25Config())
	if err != nil || len(result) != 1 || result[0].DocumentID != "doc" {
		t.Fatalf("Chinese lexical retrieval: %v %v", result, err)
	}
	result, err = RankBM25(context.Background(), "库", chunks, allowed, 1, DefaultBM25Config())
	if err != nil || len(result) != 1 {
		t.Fatalf("single Han character did not match: %v %v", result, err)
	}
	result, err = RankBM25(context.Background(), "unrelated", chunks, allowed, 1, DefaultBM25Config())
	if err != nil || len(result) != 0 {
		t.Fatalf("unrelated content returned: %v %v", result, err)
	}
}

func TestBM25DeterministicTiesAndLengthNormalization(t *testing.T) {
	chunks := []Chunk{{ID: "b", DocumentID: "two", DocumentVersion: "v1", Text: "go"}, {ID: "a", DocumentID: "one", DocumentVersion: "v1", Text: "go"}, {ID: "long", DocumentID: "three", DocumentVersion: "v1", Text: "go java python kotlin ruby"}}
	result, err := RankBM25(context.Background(), "go go", chunks, map[string]string{"one": "v1", "two": "v1", "three": "v1"}, 3, DefaultBM25Config())
	if err != nil || len(result) != 3 || result[0].DocumentID != "one" || result[1].DocumentID != "two" || result[2].DocumentID != "three" {
		t.Fatalf("tie or length normalization: %v %v", result, err)
	}
}

func TestBM25CancellationAndInvalidAuthorizedCorpus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RankBM25(ctx, "query", nil, nil, 1, DefaultBM25Config()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
	chunk := Chunk{ID: "one", DocumentID: "doc", DocumentVersion: "v1", Text: "query"}
	if _, err := RankBM25(context.Background(), "query", []Chunk{chunk, chunk}, map[string]string{"doc": "v1"}, 1, DefaultBM25Config()); !errors.Is(err, ErrInvalidChunk) {
		t.Fatalf("duplicate authorized chunk accepted: %v", err)
	}
	if _, err := RankBM25(context.Background(), "query", nil, nil, 0, DefaultBM25Config()); !errors.Is(err, ErrInvalidBM25) {
		t.Fatalf("unbounded TopK accepted: %v", err)
	}
}
