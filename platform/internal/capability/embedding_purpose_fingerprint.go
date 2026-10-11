package capability

import (
	"crypto/sha256"
	"encoding/hex"
)

func modelPurposeFingerprint(base, purpose string) string {
	if purpose == "" {
		return base
	}
	digest := sha256.Sum256([]byte(base + "|embedding-input-purpose=" + purpose))
	return hex.EncodeToString(digest[:])
}
