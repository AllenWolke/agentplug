// bootstrap-admin 是空库首次管理员维护命令，不启动 HTTP 服务或执行迁移。
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sqlutil"
)

var errPrivateConfig = errors.New("invalid private first-administrator configuration")

type configuration struct {
	Version int    `json:"version"`
	DBDSN   string `json:"db_dsn"`
	identity.FirstAdministratorRequest
}

func loadConfiguration(path string) (configuration, error) {
	var config configuration
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return config, errPrivateConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return config, errPrivateConfig
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return config, errPrivateConfig
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return config, errPrivateConfig
	}
	// 配置是扁平对象；拒绝重复字段，不能由最后一次赋值覆盖批准输入。
	keys := json.NewDecoder(bytes.NewReader(raw))
	first, err := keys.Token()
	if err != nil || first != json.Delim('{') {
		return config, errPrivateConfig
	}
	seen := map[string]bool{}
	for keys.More() {
		token, err := keys.Token()
		key, ok := token.(string)
		key = strings.ToLower(key)
		if err != nil || !ok || seen[key] {
			return config, errPrivateConfig
		}
		seen[key] = true
		var value json.RawMessage
		if keys.Decode(&value) != nil {
			return config, errPrivateConfig
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || config.Version != 1 || config.FirstAdministratorRequest.Validate() != nil {
		return config, errPrivateConfig
	}
	parsed, err := url.Parse(config.DBDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.User.Username() == "" || strings.Trim(parsed.Path, "/") == "" {
		return config, errPrivateConfig
	}
	dsn, err := pgx.ParseConfig(config.DBDSN)
	if err != nil || dsn.User == "" || strings.EqualFold(dsn.User, "root") || dsn.Database == "" || strings.EqualFold(dsn.User, "postgres") || len(dsn.RuntimeParams) != 0 || len(dsn.Password) < 16 {
		return config, errPrivateConfig
	}
	password := strings.TrimSpace(dsn.Password)
	runes := []rune(password)
	if len(password) < 16 || len(runes) == 0 || strings.Count(password, string(runes[0])) == len(runes) {
		return config, errPrivateConfig
	}
	for _, marker := range []string{"replace", "change-me", "changeme", "placeholder", "dev-internal", "dev-signing"} {
		if strings.Contains(strings.ToLower(password), marker) {
			return config, errPrivateConfig
		}
	}
	return config, nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "owner-private JSON configuration")
	if flags.Parse(args) != nil || *path == "" || flags.NArg() != 0 {
		return errPrivateConfig
	}
	config, err := loadConfiguration(*path)
	if err != nil {
		return err
	}
	db, err := sqlutil.OpenPostgres(ctx, config.DBDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	recorder := audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
	err = identity.NewSQLStore(db).InitializeFirstAdministrator(ctx, config.FirstAdministratorRequest, verifyFirstAdministratorDatabase,
		func(_ context.Context, tx *sql.Tx, request identity.FirstAdministratorRequest, now time.Time) error {
			return recorder.RecordTx(tx, audit.Event{
				ID: "identity-first-admin-bootstrap", TenantID: request.TenantID, DepartmentID: request.DepartmentID, ApplicationID: request.ApplicationID,
				ActorType: "deployment_operator", ActorID: request.OperatorID, TraceID: "first-admin-bootstrap",
				AggregateType: "identity_first_administrator", AggregateID: request.PrincipalID,
				Action: "identity.first_administrator.created", Outcome: "success",
				Summary: "Initial administrator and authentication credential provisioned; approval " + request.ApprovalReference, CreatedAt: now,
			})
		})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "FIRST ADMINISTRATOR BOOTSTRAP PASS")
	return err
}

func verifyFirstAdministratorDatabase(ctx context.Context, db *sql.DB) error {
	if err := schemaversion.Check(ctx, db); err != nil {
		return err
	}
	return schemaversion.CheckRuntimePrivileges(ctx, db)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "first administrator bootstrap failed; inspect private config, current schema, empty identity state and DML privileges")
		os.Exit(1)
	}
}
