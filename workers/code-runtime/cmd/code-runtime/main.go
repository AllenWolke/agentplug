// The controller is an operator service. Agents cannot supply its configuration
// or acquire its Docker access, signing authority, or state encryption key.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lexagent/code-runtime/internal/gateway"
	"github.com/lexagent/code-runtime/internal/sandbox"
)

type config struct {
	ListenAddress      string            `json:"listen_address"`
	ControllerID       string            `json:"controller_id"`
	PublicKeyFile      string            `json:"public_key_file"`
	StateKeyFile       string            `json:"state_key_file"`
	StateDirectory     string            `json:"state_directory"`
	DockerConfigDir    string            `json:"docker_config_directory"`
	Owner              string            `json:"owner"`
	Images             map[string]string `json:"images"`
	Profiles           []gateway.Profile `json:"profiles"`
	MaxConcurrent      int               `json:"max_concurrent"`
	TLSCertificateFile string            `json:"tls_certificate_file,omitempty"`
	TLSPrivateKeyFile  string            `json:"tls_private_key_file,omitempty"`
}

func readBounded(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("operator file must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return nil, errors.New("operator file unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("operator file unavailable")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("operator file unavailable")
	}
	return body, nil
}

func readKey(path string, size int) ([]byte, error) {
	body, err := readBounded(path, 1024)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	key, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(body)))
	if err != nil || len(key) != size {
		clear(key)
		return nil, errors.New("operator key invalid")
	}
	return key, nil
}

func run(ctx context.Context) error {
	body, err := readBounded(os.Getenv("CODE_RUNTIME_CONFIG_FILE"), 1<<20)
	if err != nil {
		return err
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("operator configuration invalid")
	}
	var certificate *tls.Certificate
	if cfg.TLSCertificateFile != "" || cfg.TLSPrivateKeyFile != "" {
		publicPEM, certErr := readBounded(cfg.TLSCertificateFile, 64<<10)
		privatePEM, keyErr := readBounded(cfg.TLSPrivateKeyFile, 16<<10)
		defer clear(privatePEM)
		if certErr != nil || keyErr != nil {
			return errors.New("controller TLS material unavailable")
		}
		pair, err := tls.X509KeyPair(publicPEM, privatePEM)
		clear(privatePEM)
		if err != nil {
			return errors.New("controller TLS material invalid")
		}
		certificate = &pair
	}
	address, err := netip.ParseAddrPort(cfg.ListenAddress)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" || (!address.Addr().IsLoopback() && !address.Addr().IsPrivate()) {
		return errors.New("controller requires a specific private listener")
	}
	public, err := readKey(cfg.PublicKeyFile, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	key, err := readKey(cfg.StateKeyFile, 32)
	if err != nil {
		return err
	}
	defer clear(key)
	// Directories are provisioned by operators, not created from request input.
	runner, err := sandbox.New(sandbox.Config{Owner: cfg.Owner, Images: cfg.Images, MaxConcurrent: cfg.MaxConcurrent, DockerConfigDirectory: cfg.DockerConfigDir})
	if err != nil {
		return errors.New("sandbox configuration unavailable")
	}
	handler, err := gateway.New(cfg.ControllerID, public, cfg.Profiles, runner, cfg.StateDirectory, key, cfg.MaxConcurrent)
	if err != nil {
		return errors.New("controller configuration unavailable")
	}
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return errors.New("controller listener unavailable")
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 75 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	stopped := make(chan struct{})
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		select {
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if server.Shutdown(cleanup) != nil {
				_ = server.Close()
			}
		case <-stopped:
		}
	}()
	if certificate != nil {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*certificate}}
		err = server.ServeTLS(listener, "", "")
	} else {
		err = server.Serve(listener)
	}
	close(stopped)
	<-cleanupDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return errors.New("controller server stopped unexpectedly")
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		// All errors above are fixed messages. Never print source, permits or keys.
		log.Fatal(err)
	}
}
