package architecture_test

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

type readProjection struct {
	File         string `json:"file"`
	Owner        string `json:"owner"`
	Table        string `json:"table"`
	SourceSHA256 string `json:"source_sha256"`
	QuerySHA256  string `json:"query_sha256"`
	Reason       string `json:"reason"`
}

func readOnlyProjectionQuery(query string) bool {
	if !regexp.MustCompile(`(?i)^\s*(SELECT|WITH)\b`).MatchString(query) {
		return false
	}
	syntax := regexp.MustCompile(`\$[1-9][0-9]*\b`).ReplaceAllString(query, "?")
	for _, token := range []string{";", "--", "/*", "$"} {
		if strings.Contains(syntax, token) {
			return false
		}
	}
	sanitized := regexp.MustCompile(`'(?:''|[^'])*'`).ReplaceAllString(query, "''")
	return !regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|CALL|DO)\b`).MatchString(sanitized)
}

func projectionTables(owner, relative string, source []byte, query string, complete bool, projections []readProjection) map[string]bool {
	allowed := map[string]bool{}
	if !complete || !readOnlyProjectionQuery(query) {
		return allowed
	}
	sourceHash := sha256.Sum256(source)
	queryHash := sha256.Sum256([]byte(strings.Join(strings.Fields(query), " ")))
	for _, p := range projections {
		if p.File == "platform/internal/"+relative && p.Owner == owner &&
			p.SourceSHA256 == hex.EncodeToString(sourceHash[:]) && p.QuerySHA256 == hex.EncodeToString(queryHash[:]) &&
			strings.TrimSpace(p.Reason) != "" {
			allowed[p.Table] = true
		}
	}
	return allowed
}

func TestReadProjectionRequiresExactSourceAndQuery(t *testing.T) {
	source := []byte("reviewed source")
	query := "SELECT id FROM foreign_table"
	s := sha256.Sum256(source)
	q := sha256.Sum256([]byte(query))
	projection := []readProjection{{File: "platform/internal/audit/projection.go", Owner: "audit", Table: "foreign_table", SourceSHA256: hex.EncodeToString(s[:]), QuerySHA256: hex.EncodeToString(q[:]), Reason: "reviewed bounded read"}}
	for _, fixture := range []struct {
		name, owner, path, query string
		source                   []byte
		complete, allowed        bool
	}{
		{"reviewed", "audit", "audit/projection.go", query, source, true, true},
		{"source-changed", "audit", "audit/projection.go", query, []byte("changed"), true, false},
		{"query-changed", "audit", "audit/projection.go", query + " JOIN other_table ON true", source, true, false},
		{"wrong-owner", "identity", "audit/projection.go", query, source, true, false},
		{"wrong-file", "audit", "audit/other.go", query, source, true, false},
		{"dynamic", "audit", "audit/projection.go", query, source, false, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			got := projectionTables(fixture.owner, fixture.path, fixture.source, fixture.query, fixture.complete, projection)
			if got["foreign_table"] != fixture.allowed {
				t.Fatalf("projection allowed = %v", got)
			}
		})
	}
	// Even a freshly signed registry cannot authorize a write or a second statement.
	for _, query := range []string{"UPDATE foreign_table SET id=1", "WITH deleted AS (DELETE FROM foreign_table RETURNING *) SELECT * FROM deleted", "SELECT id FROM foreign_table; DELETE FROM foreign_table", "SELECT id FROM foreign_table FOR UPDATE"} {
		if readOnlyProjectionQuery(query) {
			t.Fatalf("write accepted as read: %s", query)
		}
	}
}
