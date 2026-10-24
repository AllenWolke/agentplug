package sharedkernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

var checkpointName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// CheckpointIdentity is shared wire identity math, not a State read or grant.
func CheckpointIdentity(scope Scope, namespace, key string) (string, string, error) {
	if scope.ValidateTrusted() != nil || !checkpointName.MatchString(namespace) || !checkpointName.MatchString(key) {
		return "", "", fmt.Errorf("invalid checkpoint identity")
	}
	encoded, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, scope.InstallationID, scope.AgentVersionID, scope.SessionID, scope.RunID})
	prefix := sha256.Sum256(encoded)
	encoded, _ = json.Marshal([]string{hex.EncodeToString(prefix[:]), namespace, key})
	id := sha256.Sum256(encoded)
	return hex.EncodeToString(prefix[:]), hex.EncodeToString(id[:]), nil
}
