package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lexagent/platform/internal/reversibleapi"
	"github.com/lexagent/platform/internal/sqlutil"
)

type config struct {
	ToolName         string   `json:"tool_name"`
	TenantID         string   `json:"tenant_id"`
	ApplicationID    string   `json:"application_id"`
	AgentIDs         []string `json:"agent_ids"`
	ForwardTokenFile string   `json:"forward_token_file"`
	ControlTokenFile string   `json:"control_token_file"`
}

func readFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > int64(limit) {
		return nil, errors.New("private configuration unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private configuration unavailable")
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(body) > limit {
		return nil, errors.New("private configuration unavailable")
	}
	return body, nil
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dsn, err := readFile(os.Getenv("REVERSIBLE_API_DSN_FILE"), 8192)
	if err != nil {
		log.Fatal("private database configuration unavailable")
	}
	db, err := sqlutil.OpenPostgres(ctx, strings.TrimSpace(string(dsn)))
	clear(dsn)
	if err != nil {
		log.Fatal("database unavailable")
	}
	defer db.Close()
	if len(os.Args) == 2 && os.Args[1] == "migrate" {
		if reversibleapi.Migrate(ctx, db) != nil {
			log.Fatal("explicit API migration failed")
		}
		log.Print("explicit API migration complete")
		return
	}
	if len(os.Args) > 1 {
		log.Fatal("usage: reversible-api [migrate]")
	}
	body, err := readFile(os.Getenv("REVERSIBLE_API_CONFIG_FILE"), 16384)
	if err != nil {
		log.Fatal("API configuration unavailable")
	}
	var c config
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		log.Fatal("API configuration invalid")
	}
	forward, err := readFile(c.ForwardTokenFile, 8192)
	if err != nil {
		log.Fatal("forward credential unavailable")
	}
	defer clear(forward)
	control, err := readFile(c.ControlTokenFile, 8192)
	if err != nil {
		log.Fatal("control credential unavailable")
	}
	defer clear(control)
	server, err := reversibleapi.New(ctx, db, reversibleapi.Config{ToolName: c.ToolName, TenantID: c.TenantID, ApplicationID: c.ApplicationID, AgentIDs: c.AgentIDs, ForwardToken: bytes.TrimSpace(forward), ControlToken: bytes.TrimSpace(control)})
	if err != nil {
		log.Fatal("API runtime not ready; check explicit migration and configuration")
	}
	address := os.Getenv("REVERSIBLE_API_LISTEN")
	if address == "" {
		address = "127.0.0.1:8087"
	}
	httpServer := &http.Server{Addr: address, Handler: server, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		httpServer.Shutdown(shutdown)
	}()
	// Deploy behind an operator-owned TLS service. The platform client enforces
	// HTTPS/allowlist; HTTP is restricted to explicit local development.
	cert, key := os.Getenv("REVERSIBLE_API_TLS_CERT_FILE"), os.Getenv("REVERSIBLE_API_TLS_KEY_FILE")
	if cert != "" || key != "" {
		if cert == "" || key == "" {
			log.Fatal("both TLS certificate and key required")
		}
		if _, err = readFile(cert, 256<<10); err != nil {
			log.Fatal("TLS certificate unavailable")
		}
		keyBytes, keyErr := readFile(key, 16384)
		clear(keyBytes)
		if keyErr != nil {
			log.Fatal("TLS key unavailable")
		}
		err = httpServer.ListenAndServeTLS(cert, key)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("API listener failed")
	}
}
