// Package knowledge contains platform-owned retrieval and indexing primitives.
package knowledge

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidQuery = errors.New("invalid lexical query")
	ErrInvalidChunk = errors.New("invalid authorized knowledge chunk")
	ErrInvalidBM25  = errors.New("invalid BM25 configuration")
)

type Chunk struct {
	ID              string
	DocumentID      string
	DocumentVersion string
	Text            string
}

type RankedChunk struct {
	Chunk
	Score float64
}

type BM25Config struct {
	K1 float64
	B  float64
}

func DefaultBM25Config() BM25Config { return BM25Config{K1: 1.2, B: 0.75} }

const TokenizerVersion = "unicode-word-han-unigram-bigram-v1"

// LexicalTokens uses lowercase letter/number words and overlapping Han
// bigrams. Indexing and querying must use this same versioned tokenizer.
// Han unigrams are included so single-character queries can match passages.
func LexicalTokens(text string) ([]string, error) {
	if len(text) > 1<<20 || !utf8.ValidString(text) {
		return nil, ErrInvalidChunk
	}
	var result []string
	var word, han []rune
	flushWord := func() {
		if len(word) > 0 {
			result = append(result, strings.ToLower(string(word)))
			word = nil
		}
	}
	flushHan := func() {
		for _, character := range han {
			result = append(result, string(character))
		}
		for index := 0; index+1 < len(han); index++ {
			result = append(result, string(han[index:index+2]))
		}
		han = nil
	}
	for _, character := range text {
		switch {
		case unicode.Is(unicode.Han, character):
			flushWord()
			han = append(han, character)
		case unicode.IsLetter(character) || unicode.IsDigit(character):
			flushHan()
			word = append(word, character)
		default:
			flushWord()
			flushHan()
		}
	}
	flushWord()
	flushHan()
	return result, nil
}

// RankBM25 derives passage frequencies and length statistics only from the
// supplied current authorized document versions. The caller must obtain that
// map from trusted, live authority, never from Agent/user request metadata.
// Final content/citation authorization must still be checked after retrieval.
// Unauthorized and stale chunks are discarded before reading their content.
func RankBM25(ctx context.Context, query string, chunks []Chunk, currentAuthorizedVersions map[string]string, topK int, config BM25Config) ([]RankedChunk, error) {
	if math.IsNaN(config.K1) || math.IsInf(config.K1, 0) || config.K1 <= 0 || config.K1 > 10 || math.IsNaN(config.B) || math.IsInf(config.B, 0) || config.B < 0 || config.B > 1 || topK < 1 || topK > 100 {
		return nil, ErrInvalidBM25
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	queryTokens, err := LexicalTokens(query)
	if err != nil || len(queryTokens) == 0 {
		return nil, ErrInvalidQuery
	}
	queryTerms := make(map[string]bool)
	for _, token := range queryTokens {
		queryTerms[token] = true
	}
	type passage struct {
		chunk  Chunk
		length int
		counts map[string]int
	}
	type chunkKey struct{ document, chunk string }
	seen := make(map[chunkKey]bool)
	var passages []passage
	df := make(map[string]int)
	totalLength := 0
	for _, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		version, allowed := currentAuthorizedVersions[chunk.DocumentID]
		if !allowed || version == "" || version != chunk.DocumentVersion {
			continue
		}
		key := chunkKey{chunk.DocumentID, chunk.ID}
		if chunk.ID == "" || chunk.DocumentID == "" || seen[key] {
			return nil, ErrInvalidChunk
		}
		seen[key] = true
		tokens, err := LexicalTokens(chunk.Text)
		if err != nil {
			return nil, err
		}
		if len(tokens) == 0 {
			continue
		}
		counts := make(map[string]int)
		for _, token := range tokens {
			if queryTerms[token] {
				counts[token]++
			}
		}
		for token := range counts {
			df[token]++
		}
		passages = append(passages, passage{chunk: chunk, length: len(tokens), counts: counts})
		totalLength += len(tokens)
	}
	if len(passages) == 0 {
		return []RankedChunk{}, nil
	}
	averageLength := float64(totalLength) / float64(len(passages))
	// Sorting terms also makes floating-point accumulation deterministic.
	terms := make([]string, 0, len(queryTerms))
	for token := range queryTerms {
		terms = append(terms, token)
	}
	sort.Strings(terms)
	var result []RankedChunk
	for _, passage := range passages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		score := 0.0
		for _, token := range terms {
			frequency := float64(passage.counts[token])
			if frequency == 0 {
				continue
			}
			idf := math.Log1p((float64(len(passages)-df[token]) + 0.5) / (float64(df[token]) + 0.5))
			normalization := config.K1 * (1 - config.B + config.B*float64(passage.length)/averageLength)
			score += idf * frequency * (config.K1 + 1) / (frequency + normalization)
		}
		if score > 0 {
			result = append(result, RankedChunk{Chunk: passage.chunk, Score: score})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if result[i].DocumentID != result[j].DocumentID {
			return result[i].DocumentID < result[j].DocumentID
		}
		return result[i].ID < result[j].ID
	})
	if len(result) > topK {
		result = result[:topK]
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
