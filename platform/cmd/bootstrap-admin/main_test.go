package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/identity"
)

func fixtureConfiguration(t *testing.T) configuration {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return configuration{Version: 1, DBDSN: "postgres://bootstrap_dml:" + hex.EncodeToString(raw[:]) + "@127.0.0.1:5432/fixture?sslmode=disable",
		FirstAdministratorRequest: identity.FirstAdministratorRequest{TenantID: "tenant-first", TenantName: "First tenant", DepartmentID: "dept-first", DepartmentName: "First department", ApplicationID: "app-first", ApplicationName: "First application", PrincipalID: "first.admin", OperatorID: "deployment.owner", Issuer: "https://idp.fixture.internal/realm", Subject: "subject-initial-admin", ApprovalReference: "change-001"}}
}

func writeConfig(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrivateConfigurationStrictParsing(t *testing.T) {
	config := fixtureConfiguration(t)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfiguration(writeConfig(t, raw)); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"trailing":       append(append([]byte{}, raw...), []byte("{}")...),
		"unknown":        append([]byte(`{"unapproved":true,`), raw[1:]...),
		"duplicate":      append([]byte(`{"version":1,`), raw[1:]...),
		"case duplicate": append([]byte(`{"VERSION":1,`), raw[1:]...),
		"oversize":       []byte(strings.Repeat(" ", 65537)),
		"invalid":        []byte(`{"version":`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfiguration(writeConfig(t, content)); err == nil {
				t.Fatal("unapproved configuration accepted")
			}
		})
	}
}

func TestPrivateConfigurationRejectsUnsafeInputs(t *testing.T) {
	for _, field := range []string{"root", "short", "repeated", "placeholder", "missing database", "administrator", "unsupported startup parameter", "mysql driver", "subject", "issuer", "unknown version"} {
		t.Run(field, func(t *testing.T) {
			config := fixtureConfiguration(t)
			switch field {
			case "root":
				config.DBDSN = strings.Replace(config.DBDSN, "bootstrap_dml:", "root:", 1)
			case "short":
				config.DBDSN = "postgres://dml:short@127.0.0.1/fixture"
			case "repeated":
				config.DBDSN = "postgres://dml:" + strings.Repeat("密", 16) + "@127.0.0.1/fixture"
			case "placeholder":
				config.DBDSN = "postgres://dml:replace-with-strong-password@127.0.0.1/fixture"
			case "missing database":
				config.DBDSN = strings.Replace(config.DBDSN, "/fixture?", "/?", 1)
			case "administrator":
				config.DBDSN = strings.Replace(config.DBDSN, "bootstrap_dml:", "postgres:", 1)
			case "unsupported startup parameter":
				config.DBDSN += "&search_path=untrusted"
			case "mysql driver":
				config.DBDSN = "mysql://dml:synthetic-test-password@127.0.0.1/fixture"
			case "subject":
				config.Subject = "REPLACE_SUBJECT"
			case "issuer":
				config.Issuer = "http://idp.fixture.internal/realm"
			case "unknown version":
				config.Version = 2
			}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfiguration(writeConfig(t, raw)); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestPrivateFilePermissionsAndLinks(t *testing.T) {
	raw, err := json.Marshal(fixtureConfiguration(t))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, raw)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfiguration(path); err == nil {
			t.Fatal("public config accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "symlink.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfiguration(link); err == nil {
			t.Fatal("symlink config accepted")
		}
	}
}

func TestCommandRejectsAmbientCredentialsAndMissingConfig(t *testing.T) {
	t.Setenv("DB_DSN", fixtureConfiguration(t).DBDSN)
	var output bytes.Buffer
	for _, args := range [][]string{nil, {"--dsn", "not-approved"}, {"--config", "missing", "extra"}} {
		if err := run(context.Background(), args, &output); err == nil {
			t.Fatal("command accepted without a private config")
		}
	}
	if output.Len() != 0 {
		t.Fatal("failed command emitted success")
	}
}
