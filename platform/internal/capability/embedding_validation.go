package capability

import "math"

func validEmbeddingVectors(vectors [][]float32, count int) bool {
	if count < 1 || len(vectors) != count || len(vectors[0]) < 1 || len(vectors[0]) > 4096 {
		return false
	}
	dimensions := len(vectors[0])
	for _, vector := range vectors {
		if len(vector) != dimensions {
			return false
		}
		norm := float64(0)
		for _, value := range vector {
			if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
				return false
			}
			norm += float64(value) * float64(value)
		}
		if norm == 0 {
			return false
		}
	}
	return true
}
