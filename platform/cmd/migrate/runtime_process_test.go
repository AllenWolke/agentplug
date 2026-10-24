package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

// Build and launch the real platform executable, not a lifecycle fake.
// 编译并启动真实平台可执行程序，不用生命周期替身代替主进程。
func TestSQLRealPlatformProcessStartsWithDMLAndRejectsBadSchema(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	uri, err := url.Parse(dsn)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" {
		t.Fatal("dedicated loopback PostgreSQL fixture required")
	}
	root, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	name := fmt.Sprintf("runtime_process_%d", time.Now().UnixNano())
	if _, err = root.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := root.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	uri.Path = "/" + name
	adminDSN := uri.String()
	processTimeout := 2 * time.Minute
	if os.Getenv("PLATFORM_TEST_CHECKPOINT_RECOVERY") == "1" {
		processTimeout = 4 * time.Minute
	}
	if os.Getenv("PLATFORM_TEST_EVALUATION_RESTART") == "1" {
		processTimeout = 4 * time.Minute
	}
	if os.Getenv("PLATFORM_TEST_LIVE_MODELS") == "1" {
		processTimeout = 8 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	t.Setenv("PLATFORM_DEV_RUNTIME_PASSWORD", "")
	config := bootstrap.Config{Runtime: bootstrap.RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", DBDSN: adminDSN, EventBusMode: "disabled"}}
	if err = run(ctx, config); err != nil {
		t.Fatal(err)
	}
	db, err := sqlutil.OpenPostgres(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user := fmt.Sprintf("process_%d", time.Now().UnixNano())
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := fmt.Sprintf("%x", secret)
	if _, err = db.Exec(`CREATE ROLE "` + user + `" LOGIN PASSWORD '` + password + `'`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(`DROP OWNED BY "` + user + `"`); err != nil {
			t.Error(err)
		}
		if _, err := root.Exec(`DROP ROLE "` + user + `"`); err != nil {
			t.Error(err)
		}
	}()
	for _, query := range []string{
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		`REVOKE TEMPORARY ON DATABASE "` + name + `" FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE "` + name + `" TO "` + user + `"`,
		`GRANT USAGE ON SCHEMA public,knowledge TO "` + user + `"`,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public,knowledge TO "` + user + `"`,
		`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public,knowledge TO "` + user + `"`,
		`REVOKE INSERT,UPDATE,DELETE ON platform_schema_version FROM "` + user + `"`,
	} {
		if _, err = db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	uri.User = url.UserPassword(user, password)
	runtimeDSN := uri.String()
	limited, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	if _, err = limited.Exec(`CREATE TABLE forbidden_process_ddl(id INT)`); err == nil {
		t.Fatal("runtime fixture unexpectedly allows DDL")
	}
	binary := filepath.Join(t.TempDir(), "platform-runtime")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.CommandContext(ctx, "go", "build", "-race", "-o", binary, "../platform").CombinedOutput(); err != nil {
		t.Fatalf("build platform process: %v %s", err, out)
	}
	if os.Getenv("PLATFORM_TEST_CHECKPOINT_RECOVERY") != "1" {
		// Keep the index-worker acceptance run ahead of browser-session fixtures:
		// the latter intentionally leave remote-stop-pending Runs after the test
		// process shuts down, and those unrelated owners must not starve worker startup.
		// 索引 worker 先于浏览器会话夹具运行，避免无关的远端停止待确认 Run 干扰启动。
		t.Run("knowledge-index-worker", func(t *testing.T) {
			environment, verify := prepareRuntimeIndexFixture(t, ctx, db, runtimeDSN)
			launchPlatformFixtureWithOptions(t, ctx, binary, runtimeDSN, true, environment, verify)
		})
	}
	launchPlatformFixture(t, ctx, binary, runtimeDSN, true)
	if os.Getenv("PLATFORM_TEST_CHECKPOINT_RECOVERY") == "1" {
		t.Run("checkpoint-agent-process-recovery", func(t *testing.T) {
			verifyRuntimeCheckpointRecovery(t, ctx, binary, runtimeDSN, db)
		})
	}
	if os.Getenv("PLATFORM_TEST_EVALUATION_RESTART") == "1" {
		t.Run("evaluation-seed-process-restart", func(t *testing.T) {
			verifyRuntimeEvaluationSeedRestart(t, ctx, binary, runtimeDSN, adminDSN, db)
		})
	}
	if _, err := db.Exec(`UPDATE platform_schema_version SET checksum='invalid'`); err != nil {
		t.Fatal(err)
	}
	launchPlatformFixture(t, ctx, binary, runtimeDSN, false)
	if _, err := db.Exec(`DELETE FROM platform_schema_version`); err != nil {
		t.Fatal(err)
	}
	launchPlatformFixture(t, ctx, binary, runtimeDSN, false)
}

func launchPlatformFixture(t *testing.T, ctx context.Context, binary, dsn string, wantReady bool) {
	launchPlatformFixtureWithOptions(t, ctx, binary, dsn, wantReady, nil, nil)
}

func launchPlatformFixtureWithOptions(t *testing.T, ctx context.Context, binary, dsn string, wantReady bool, extraEnvironment []string, verify func(*http.Client, string)) {
	if wantReady && verify == nil {
		seedRuntimeReviewHistory(t, ctx, dsn)
		seedRuntimeAccessHistory(t, ctx, dsn)
	}
	launchPlatformFixtureWithControl(t, ctx, binary, dsn, wantReady, extraEnvironment, func(client *http.Client, address string, _ func()) {
		if verify != nil {
			verify(client, address)
		} else {
			assertRuntimeGatewayBoundary(t, client, address)
			assertRuntimeBrowserSessionRevocation(t, ctx, client, address, dsn)
		}
	})
}

// The controller can crash only this owned process, and waits for OS exit.
func launchPlatformFixtureWithControl(t *testing.T, ctx context.Context, binary, dsn string, wantReady bool, extraEnvironment []string, verify func(*http.Client, string, func())) {
	t.Helper()
	address := func() string {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		return a
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicAddr, internalAddr := address(), address()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(os.Environ(), "APP_ENV=development", "DB_DRIVER=pgx", "DB_DSN="+dsn, "PLATFORM_HTTP_ADDR="+publicAddr, "PLATFORM_INTERNAL_ADDR="+internalAddr, "INTERNAL_TOKEN=fixture-internal-token-with-32-bytes", "INTERNAL_SIGNING_SECRET=fixture-signing-secret-with-32-bytes", "PLATFORM_CONTEXT_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(public), "PLATFORM_CONTEXT_PRIVATE_KEY="+base64.StdEncoding.EncodeToString(private), "PLATFORM_DEMO_IDENTITY_BOOTSTRAP=false", "EVENT_BUS_MODE=disabled", "PLATFORM_POLICY_RESOLVER=sql", "PLATFORM_POLICY_BOOTSTRAP_JSON=", "PLATFORM_PROMPT_TEMPLATES_JSON=", "PLATFORM_RUN_EXECUTOR=platform", "OTEL_EXPORTER_OTLP_ENDPOINT=", "KNOWLEDGE_DATABASE_DSN=", "PLATFORM_METRIC_RUNNER_URL=http://127.0.0.1:9", "PLATFORM_METRIC_RUNNER_TOKEN=fixture-metric-token")
	var output bytes.Buffer
	cmd.Env = append(cmd.Env, "BROWSER_GATEWAY_TOKEN=gateway-fixture-0123456789abcdef0123456789abcdef")
	cmd.Env = append(cmd.Env, extraEnvironment...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	t.Cleanup(func() {
		if t.Failed() {
			text := strings.ReplaceAll(output.String(), dsn, "[redacted DSN]")
			if len(text) > 32768 {
				text = text[len(text)-32768:]
			}
			t.Logf("platform process failure diagnostics: %s", text)
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var processErr error
	go func() { processErr = cmd.Wait(); close(done) }()
	crash := func() {
		t.Helper()
		select {
		case <-done:
			t.Fatal("owned platform already exited")
		default:
		}
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal("crash owned platform", err)
		}
		<-done
	}
	defer func() {
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Kill()
		<-done
	}()
	if !wantReady {
		select {
		case <-done:
			if processErr == nil || !strings.Contains(output.String(), "schema version is incompatible") {
				t.Fatal("invalid schema was not rejected explicitly")
			}
		case <-time.After(15 * time.Second):
			t.Fatal("invalid schema did not stop startup")
		}
		return
	}
	client := http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatalf("DML-only process exited before readiness: %v %s", processErr, strings.ReplaceAll(output.String(), dsn, "[redacted DSN]"))
		default:
		}
		resp, err := client.Get("http://" + publicAddr + "/health/ready")
		if err == nil {
			status := resp.StatusCode
			_ = resp.Body.Close()
			if status == http.StatusOK {
				verify(&client, publicAddr, crash)
				select {
				case <-done:
					return // Explicit crash callback has already observed OS exit.
				default:
				}
				if err := cmd.Process.Signal(os.Interrupt); err != nil {
					t.Fatal("signal runtime shutdown", err)
				}
				select {
				case <-done:
					if processErr != nil {
						t.Fatal("runtime shutdown failed", processErr)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("runtime failed graceful shutdown")
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("DML-only process never became ready")
}

func assertRuntimeGatewayBoundary(t *testing.T, client *http.Client, address string) {
	t.Helper()
	boundaryClient := *client
	boundaryClient.Timeout = 15 * time.Second
	for _, tc := range []struct {
		path, token, browser string
		status               int
	}{
		{"/modules/identity/principals", "fixture-internal-token-with-32-bytes", "1", 403},
		{"/modules/knowledge/sources/docs", "fixture-internal-token-with-32-bytes", "1", 403},
		{"/modules/knowledge/sources/docs", "gateway-fixture-0123456789abcdef0123456789abcdef", "1", 401},
		{"/modules/identity/workload-bindings", "fixture-internal-token-with-32-bytes", "", 403},
		{"/modules/identity/grants", "fixture-internal-token-with-32-bytes", "", 403},
		{"/modules/execution/platform/runs", "fixture-internal-token-with-32-bytes", "", 403},
		{"/modules/execution/platform/runs/forged/transition", "fixture-internal-token-with-32-bytes", "", 403},
		{"/modules/execution/platform/runs/forged/cancel", "fixture-internal-token-with-32-bytes", "", 403},
		{"/modules/identity/internal/credentials/verify", "fixture-internal-token-with-32-bytes", "", 403},
		{"/modules/identity/internal/credentials/verify", "gateway-fixture-0123456789abcdef0123456789abcdef", "1", 403},
		{"/modules/identity/internal/credentials/verify", "gateway-fixture-0123456789abcdef0123456789abcdef", "", 401},
		{"/modules/conversation/shares/" + strings.Repeat("A", 43), "gateway-fixture-0123456789abcdef0123456789abcdef", "", 404},
		{"/modules/conversation/shares/" + strings.Repeat("A", 43), "fixture-internal-token-with-32-bytes", "", 403},
	} {
		method := http.MethodPost
		if strings.HasPrefix(tc.path, "/modules/conversation/shares/") {
			method = http.MethodGet
		}
		r, err := http.NewRequest(method, "http://"+address+tc.path, strings.NewReader(`{"username":"unknown.fixture","password":"invalid-fixture-password"}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Internal-Token", tc.token)
		r.Header.Set("X-Browser-Module", tc.browser)
		for key, value := range map[string]string{"X-Principal-Type": "user", "X-Principal-ID": "forged.admin", "X-Tenant-ID": "t", "X-Department-ID": "d", "X-Application-ID": "a"} {
			r.Header.Set(key, value)
		}
		resp, err := boundaryClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("actual platform gateway boundary path=%s browser=%s status=%d want=%d", tc.path, tc.browser, resp.StatusCode, tc.status)
		}
	}
}
