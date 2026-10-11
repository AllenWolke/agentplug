// Package sqlutil holds PostgreSQL connection and parameter helpers. It does
// not translate SQL dialects: repositories own explicit PostgreSQL statements.
package sqlutil

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// OpenPostgres never includes a credential-bearing DSN in returned errors.
// Driver choice is fixed. Schema migration and runtime privilege validation
// remain separate, explicit operations.
func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil || strings.TrimSpace(dsn) == "" || config.Database == "" || config.User == "" {
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(32)
	db.SetMaxIdleConns(8)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, errors.New("PostgreSQL connection unavailable")
	}
	return db, nil
}

func SQLState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
func IsUniqueViolation(err error) bool { return SQLState(err) == "23505" }

// Bind numbers repository parameter markers after dynamic WHERE/SET fragments
// are composed. Quoted text/identifiers, comments and dollar-quoted bodies are
// preserved. Native PostgreSQL $n statements pass through. JSON existence uses
// jsonb_exists(), not the question-mark operator, in statements using Bind.
// This is parameter binding only; UPSERT, types, locks and JSON remain explicit.
func Bind(query string) string {
	var out strings.Builder
	parameter := 0
	for i := 0; i < len(query); {
		start := i
		switch {
		case query[i] == '\'' || query[i] == '"':
			quote := query[i]
			i++
			for i < len(query) {
				if query[i] == quote {
					i++
					if i < len(query) && query[i] == quote {
						i++
						continue
					}
					break
				}
				i++
			}
		case strings.HasPrefix(query[i:], "--"):
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case strings.HasPrefix(query[i:], "/*"):
			i += 2
			depth := 1
			for i < len(query) && depth > 0 {
				if strings.HasPrefix(query[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(query[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
		case query[i] == '$':
			end := i + 1
			for end < len(query) && ((query[end] >= 'a' && query[end] <= 'z') || (query[end] >= 'A' && query[end] <= 'Z') || query[end] == '_' || (end > i+1 && query[end] >= '0' && query[end] <= '9')) {
				end++
			}
			if end < len(query) && query[end] == '$' {
				tag := query[i : end+1]
				closeAt := strings.Index(query[end+1:], tag)
				if closeAt < 0 {
					i = len(query)
				} else {
					i = end + 1 + closeAt + len(tag)
				}
			} else {
				i++
			}
		case query[i] == '?':
			parameter++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(parameter))
			i++
			continue
		default:
			i++
		}
		out.WriteString(query[start:i])
	}
	return out.String()
}
