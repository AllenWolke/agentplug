package execution

import (
	"encoding/json"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/jsonvaluecache"
)

// Only immutable, non-secret command metadata is reused. The caller must
// freshly validate Run/session/dispatch/lease before using this projection.
// Neither an action decision nor the bearer token or business input is kept.
type commandAuthorityHeader struct {
	Operation         string
	InputSchema       string
	ContextTokenEmpty bool
}

func parseCommandAuthorityHeader(raw []byte) (commandAuthorityHeader, error) {
	// Decode the same complete type as the original classification path. A
	// narrow struct would incorrectly accept malformed input/resume/scope types.
	var command contract.ExecuteRequest
	if err := json.Unmarshal(raw, &command); err != nil {
		return commandAuthorityHeader{}, err
	}
	return commandAuthorityHeader{command.Operation, command.InputSchema, command.ContextToken == ""}, nil
}

var commandAuthorityHeaders = jsonvaluecache.New(64, 16<<20,
	parseCommandAuthorityHeader, func(value commandAuthorityHeader) commandAuthorityHeader { return value })
