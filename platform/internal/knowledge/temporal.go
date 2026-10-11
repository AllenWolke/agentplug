package knowledge

import (
	"errors"
	"time"
)

var ErrDocumentValidityUnavailable = errors.New("knowledge document business-date validity unavailable")

// BusinessDate applies legal applicability, independently of live IAM/ACL.
// Dates are calendar days in [effective_date, valid_to); an absent end is open.
// Missing/invalid dates cannot be treated as currently applicable evidence.
func BusinessDate(metadata map[string]string, asOf string) (bool, error) {
	if asOf == "" {
		return true, nil // Existing generic corpora need not be legal documents.
	}
	day, err := time.Parse("2006-01-02", asOf)
	if err != nil {
		return false, ErrDocumentValidityUnavailable
	}
	start, err := time.Parse("2006-01-02", metadata["effective_date"])
	if err != nil {
		return false, ErrDocumentValidityUnavailable
	}
	status := metadata["status"]
	ended := status == "abolished" || status == "expired" || status == "withdrawn"
	if status != "effective" && status != "historical" && !ended {
		return false, ErrDocumentValidityUnavailable
	}
	if ended && metadata["valid_to"] == "" {
		return false, ErrDocumentValidityUnavailable
	}
	if end := metadata["valid_to"]; end != "" {
		until, err := time.Parse("2006-01-02", end)
		if err != nil || !until.After(start) {
			return false, ErrDocumentValidityUnavailable
		}
		return !day.Before(start) && day.Before(until), nil
	}
	return !day.Before(start), nil
}
