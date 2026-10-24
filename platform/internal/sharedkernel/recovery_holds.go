package sharedkernel

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrAutomaticRecoveryHeld = errors.New("automatic recovery held for operator review")

// RecoveryHolds is immutable deployment control. It grants no execution or
// inverse authority and never changes a historical operation's stored state.
type RecoveryHolds struct {
	runs    map[string]struct{}
	encoded string
}

func NewRecoveryHolds(ids []string) (RecoveryHolds, error) {
	if len(ids) > 100000 {
		return RecoveryHolds{}, ErrAutomaticRecoveryHeld
	}
	copyIDs := append([]string{}, ids...)
	runs := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || !utf8.ValidString(id) || strings.ContainsFunc(id, unicode.IsControl) {
			return RecoveryHolds{}, ErrAutomaticRecoveryHeld
		}
		if _, duplicate := runs[id]; duplicate {
			return RecoveryHolds{}, ErrAutomaticRecoveryHeld
		}
		runs[id] = struct{}{}
	}
	sort.Strings(copyIDs)
	raw, err := json.Marshal(copyIDs)
	if err != nil {
		return RecoveryHolds{}, ErrAutomaticRecoveryHeld
	}
	return RecoveryHolds{runs: runs, encoded: string(raw)}, nil
}

func (h RecoveryHolds) Contains(runID string) bool { _, found := h.runs[runID]; return found }
func (h RecoveryHolds) Len() int                   { return len(h.runs) }
func (h RecoveryHolds) RunIDsJSON() string {
	if h.encoded == "" {
		return "[]"
	}
	return h.encoded
}
