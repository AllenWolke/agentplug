package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lexagent/agent-eval/internal/service"
)

func Service(ctx context.Context, mode string, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "bundle" {
		f := flag.NewFlagSet(mode+" bundle", flag.ContinueOnError)
		dir := f.String("out", mode+"-registration", "registration bundle directory; existing files are never replaced")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *dir == "" {
			return errors.New("use bundle --out <directory>")
		}
		files, err := service.RegistrationFiles(mode)
		if err != nil {
			return err
		}
		for name := range files {
			if _, e := os.Lstat(filepath.Join(*dir, name)); !os.IsNotExist(e) {
				return errors.New("registration destination already exists or cannot be inspected")
			}
		}
		if err := os.MkdirAll(*dir, 0700); err != nil {
			return err
		}
		for _, name := range []string{"manifest.json", "input.schema.json", "output.schema.json"} {
			file, e := os.OpenFile(filepath.Join(*dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return e
			}
			_, e = file.Write(files[name])
			closeErr := file.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
		}
		fmt.Fprintln(out, "已导出公开注册资料；请通过平台完成独立审核、发布、安装和机器身份绑定："+*dir)
		return nil
	}
	if len(args) == 1 && args[0] == "manifest" {
		b, err := service.Manifest(mode)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	if len(args) < 1 || args[0] != "serve" {
		return errors.New("use judge/fixture agent serve, manifest, or bundle --out <directory>")
	}
	f := flag.NewFlagSet(mode+" serve", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:8080", "signed execution-v2 service listen address")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected service argument")
	}
	fmt.Fprintln(out, "独立评估服务启动；必须先在平台发布、安装并配置机器身份："+mode)
	return service.Serve(ctx, mode, *listen)
}

// Fixture is an explicit opt-in test API. It is not a platform runtime and
// cannot silently intercept any production Tool/Code/API binding.
func Fixture(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "agent" {
		return Service(ctx, "fixture", args[1:], out)
	}
	if len(args) == 0 || args[0] != "serve" {
		return errors.New("use fixture serve")
	}
	f := flag.NewFlagSet("fixture serve", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:8787", "fixture listen address")
	scenario := f.String("scenario", "success", "success, failure, timeout or unknown")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if *scenario != "success" && *scenario != "failure" && *scenario != "timeout" && *scenario != "unknown" && *scenario != "selectable" {
		return errors.New("unknown fixture scenario")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready", "environment": "evaluation_fixture"})
	})
	mux.HandleFunc("/fixture", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		current := *scenario
		if current == "selectable" {
			current = r.URL.Query().Get("scenario")
			if current == "success-2" {
				current = "success"
			}
			if current != "success" && current != "failure" && current != "timeout" && current != "unknown" {
				w.WriteHeader(400)
				return
			}
		}
		if current == "timeout" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch current {
		case "failure":
			w.WriteHeader(503)
		case "unknown":
			w.WriteHeader(202)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "agent-eval-fixture/v1", "scenario": current, "instruction_trust": "untrusted_data", "result": "synthetic fixture; no external side effects"})
	})
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintln(out, "独立仿真API启动；场景="+*scenario)
	e := server.ListenAndServe()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
