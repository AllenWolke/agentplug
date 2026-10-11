package knowledge

import (
	"context"
	"errors"
	"math"
	"sort"
)

var ErrInvalidHybrid = errors.New("invalid hybrid retrieval input")

type HybridConfig struct {
	RankConstant  float64
	LexicalWeight float64
	VectorWeight  float64
}

func DefaultHybridConfig() HybridConfig {
	return HybridConfig{RankConstant: 60, LexicalWeight: 1, VectorWeight: 1}
}

type HybridChunk struct {
	Chunk
	Score       float64
	LexicalRank int
	VectorRank  int
}

// FuseHybrid combines descending lexical/vector rankings with weighted RRF,
// without comparing scores measured on incompatible scales. SQL retrieval
// must enforce current document/metadata scope before its own candidate limit;
// this additional version filter cannot recover missing authorized candidates.
func FuseHybrid(ctx context.Context, lexical, vector []RankedChunk, currentAuthorizedVersions map[string]string, topK int, config HybridConfig) ([]HybridChunk, error) {
	for _, value := range []float64{config.RankConstant, config.LexicalWeight, config.VectorWeight} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
			return nil, ErrInvalidHybrid
		}
	}
	if topK < 1 || topK > 100 {
		return nil, ErrInvalidHybrid
	}
	type key struct{ document, chunk string }
	combined := make(map[key]HybridChunk)
	for branch, ranked := range [][]RankedChunk{lexical, vector} {
		seen := make(map[key]bool)
		rank := 0
		previousScore := math.Inf(1)
		for _, candidate := range ranked {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			version, allowed := currentAuthorizedVersions[candidate.DocumentID]
			if !allowed || version == "" || version != candidate.DocumentVersion {
				continue
			}
			id := key{candidate.DocumentID, candidate.ID}
			if candidate.ID == "" || candidate.DocumentID == "" || seen[id] || math.IsNaN(candidate.Score) || math.IsInf(candidate.Score, 0) || candidate.Score > previousScore {
				return nil, ErrInvalidHybrid
			}
			previousScore = candidate.Score
			seen[id] = true
			rank++
			entry, exists := combined[id]
			if exists && entry.Chunk != candidate.Chunk {
				// A citation must refer to one immutable chunk in one generation.
				return nil, ErrInvalidHybrid
			}
			entry.Chunk = candidate.Chunk
			weight := config.LexicalWeight
			if branch == 0 {
				entry.LexicalRank = rank
			} else {
				weight = config.VectorWeight
				entry.VectorRank = rank
			}
			entry.Score += weight / (config.RankConstant + float64(rank))
			if math.IsInf(entry.Score, 0) || math.IsNaN(entry.Score) {
				return nil, ErrInvalidHybrid
			}
			combined[id] = entry
		}
	}
	result := make([]HybridChunk, 0, len(combined))
	for _, entry := range combined {
		result = append(result, entry)
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
