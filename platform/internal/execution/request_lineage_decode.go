package execution

import (
	"encoding/json"
	"github.com/lexagent/platform/internal/jsonvaluecache"
)

// Only the immutable, fully validated JSON parent field is reused. Every Run
// read still supplies current scope/status/revision/lease facts from storage.
var durableParentIDs = jsonvaluecache.New(64, 4<<20, func(raw []byte) (string, error) {
	var request struct {
		Scope struct {
			ParentRunID string `json:"parent_run_id"`
		} `json:"scope"`
	}
	err := json.Unmarshal(raw, &request)
	return request.Scope.ParentRunID, err
}, func(value string) string { return value })
