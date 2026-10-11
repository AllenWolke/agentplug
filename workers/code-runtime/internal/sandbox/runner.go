// Package sandbox owns disposable Code execution environments. The controller
// has local engine access; neither code containers nor Agent processes do.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	protocol "github.com/lexagent/code-runtime-contract"
)

var ErrDenied = errors.New("code sandbox configuration denied")
var ErrBusy = errors.New("code sandbox concurrency limit reached")
var ErrUnavailable = errors.New("code sandbox unavailable")
var ErrCleanup = errors.New("code sandbox cleanup not confirmed")
var imageID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

//go:embed seccomp.json
var seccompProfile []byte

type Limits = protocol.Limits

type Request struct {
	Language string
	Code     string
	Limits   Limits
}
type Result = protocol.Result

type Config struct {
	Owner string
	// Immutable image IDs, not movable tags. The caller never chooses an image.
	Images                map[string]string
	MaxConcurrent         int
	DockerConfigDirectory string
}
type Runner struct {
	images               map[string]string
	slots                chan struct{}
	docker, host, config string
	environment          []string
	owner                string
	seccompPath          string
}

func New(config Config) (*Runner, error) {
	if config.Owner == "" {
		config.Owner = "agentplug-code-runtime"
	}
	if !regexp.MustCompile(`^[a-z0-9-]{16,96}$`).MatchString(config.Owner) {
		return nil, ErrDenied
	}
	if len(config.Images) != 3 || config.MaxConcurrent < 1 || config.MaxConcurrent > 8 || !filepath.IsAbs(config.DockerConfigDirectory) {
		return nil, ErrDenied
	}
	info, err := os.Lstat(config.DockerConfigDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrDenied
	}
	r := &Runner{images: map[string]string{}, slots: make(chan struct{}, config.MaxConcurrent), config: config.DockerConfigDirectory}
	r.owner = config.Owner
	r.seccompPath = filepath.Join(config.DockerConfigDirectory, "agentplug-code-seccomp.json")
	profileFile, profileErr := os.OpenFile(r.seccompPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(profileErr, os.ErrExist) {
		info, statErr := os.Lstat(r.seccompPath)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != int64(len(seccompProfile)) {
			return nil, ErrDenied
		}
		body, readErr := os.ReadFile(r.seccompPath)
		if readErr != nil || !bytes.Equal(body, seccompProfile) {
			return nil, ErrDenied
		}
	} else if profileErr != nil {
		return nil, ErrDenied
	} else {
		_, profileErr = profileFile.Write(seccompProfile)
		closeErr := profileFile.Close()
		if profileErr != nil || closeErr != nil {
			return nil, ErrUnavailable
		}
	}
	for _, language := range []string{"python", "javascript", "shell"} {
		id := config.Images[language]
		if !imageID.MatchString(id) {
			return nil, ErrDenied
		}
		r.images[language] = id
	}
	r.docker, err = exec.LookPath("docker")
	if err != nil {
		return nil, ErrUnavailable
	}
	switch runtime.GOOS {
	case "windows":
		r.host = "npipe:////./pipe/docker_engine"
	case "linux":
		r.host = "unix:///var/run/docker.sock"
	default:
		return nil, ErrUnavailable
	}
	// Do not inherit model keys, DB credentials or arbitrary Docker contexts.
	for _, name := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"} {
		if value := os.Getenv(name); value != "" {
			r.environment = append(r.environment, name+"="+value)
		}
	}
	r.environment = append(r.environment, "DOCKER_CONFIG="+r.config)
	for language, id := range r.images {
		if err := r.verifyExecutionImage(context.Background(), id, language); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Runner) verifyExecutionImage(ctx context.Context, id, language string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := r.capture(checkCtx, "image", "inspect", id)
	if err != nil {
		return ErrUnavailable
	}
	var rows []struct {
		ID     string `json:"Id"`
		Config struct {
			Labels     map[string]string
			User       string
			Entrypoint []string
		}
	}
	if json.Unmarshal(body, &rows) != nil || len(rows) != 1 || rows[0].ID != id || rows[0].Config.User != "65532:65532" || rows[0].Config.Labels["io.agentplug.code.filesystem-guard"] != "landlock-v3" || rows[0].Config.Labels["io.agentplug.code.language"] != language || len(rows[0].Config.Entrypoint) != 2 || rows[0].Config.Entrypoint[0] != "/usr/local/bin/code-sandbox-guard" || rows[0].Config.Entrypoint[1] != language {
		return ErrDenied
	}
	return nil
}

func (r *Runner) command(ctx context.Context, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, r.docker, append([]string{"--host", r.host, "--config", r.config}, args...)...)
	command.Env = append([]string(nil), r.environment...)
	command.WaitDelay = 2 * time.Second
	return command
}
func (r *Runner) capture(ctx context.Context, args ...string) ([]byte, error) {
	command := r.command(ctx, args...)
	output := &boundedOutput{limit: 1 << 20}
	command.Stdout = output
	command.Stderr = io.Discard
	if command.Run() != nil || output.exceeded {
		return nil, ErrUnavailable
	}
	return output.buffer.Bytes(), nil
}

type boundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	length := len(value)
	remaining := b.limit - b.buffer.Len()
	if length > remaining {
		b.exceeded = true
		value = value[:remaining]
	}
	_, _ = b.buffer.Write(value)
	if b.exceeded && b.cancel != nil {
		b.cancel()
	}
	return length, nil
}
func (b *boundedOutput) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	output := strings.ToValidUTF8(b.buffer.String(), "�")
	if len(output) > b.limit {
		output = output[:b.limit]
		for !utf8.ValidString(output) {
			output = output[:len(output)-1]
		}
		b.exceeded = true
	}
	return output, b.exceeded
}

func (r *Runner) Run(ctx context.Context, request Request) (result Result, err error) {
	image, allowed := r.images[request.Language]
	if !allowed || request.Code == "" || len(request.Code) > 64<<10 || strings.ContainsRune(request.Code, '\x00') || request.Limits.Validate() != nil {
		return result, ErrDenied
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return result, ErrBusy
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, ErrUnavailable
	}
	owner := "code-runtime-" + hex.EncodeToString(nonce[:])
	name := "agentplug-" + owner
	l := request.Limits
	args := []string{"create", "--pull", "never", "--name", name, "--label", "agentplug.test.owner=" + owner, "--label", "agentplug.code.runtime=v1", "--label", "agentplug.code.controller=" + r.owner,
		"--network", "none", "--ipc", "private", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + r.seccompPath,
		"--memory", strconv.FormatInt(l.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(l.MemoryBytes, 10), "--cpus", fmt.Sprintf("%.3f", float64(l.CPUMilli)/1000),
		"--pids-limit", strconv.Itoa(l.PIDs), "--ulimit", fmt.Sprintf("cpu=%d:%d", l.CPUSeconds, l.CPUSeconds), "--ulimit", fmt.Sprintf("fsize=%d:%d", l.DiskBytes, l.DiskBytes), "--ulimit", "nofile=64:64",
		"--tmpfs", fmt.Sprintf("/workspace:rw,nosuid,nodev,noexec,size=%d,mode=1777", l.DiskBytes-(2<<20)), "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1048576,mode=1777", "--shm-size", "1m",
		"--workdir", "/workspace", "--env", "HOME=/workspace", "--env", "TMPDIR=/workspace", "--env", "PATH=/usr/local/bin:/usr/bin:/bin", "--env", "NODE_OPTIONS=", "--env", "PYTHONPATH=",
		"--log-driver", "none", "--restart", "no", "--stop-timeout", "1", "--interactive"}
	args = append(args, "--entrypoint", "/usr/local/bin/code-sandbox-guard", image, request.Language)
	createCtx, cancelCreate := context.WithTimeout(ctx, 10*time.Second)
	raw, createErr := r.capture(createCtx, args...)
	cancelCreate()
	id := strings.TrimSpace(string(raw))
	if createErr != nil || !containerID.MatchString(id) {
		// Creation may have succeeded before the CLI acknowledgement was lost.
		if cleanupErr := r.removeOwned(name, owner); cleanupErr != nil {
			return result, cleanupErr
		}
		return result, ErrUnavailable
	}
	defer func() {
		if cleanupErr := r.removeOwned(id, owner); cleanupErr != nil {
			result.ContainerRemoved = false
			err = cleanupErr
		} else {
			result.ContainerRemoved = true
		}
	}()
	if err = r.verifyIsolation(ctx, id, owner, request.Language, l); err != nil {
		return result, err
	}
	result = Result{Version: "code-execution/v1", Status: "failed", ExitCode: -1, StartedAt: time.Now().UTC(), Limits: l, ResourceUsage: unknownResourceUsage()}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(l.TimeoutSeconds)*time.Second)
	defer cancel()
	stdout := &boundedOutput{limit: l.OutputBytes, cancel: cancel}
	stderr := &boundedOutput{limit: l.OutputBytes, cancel: cancel}
	command := r.command(callCtx, "start", "--attach", "--interactive", id)
	command.Stdin = strings.NewReader(request.Code)
	command.Stdout = stdout
	command.Stderr = stderr
	executionErr := command.Start()
	var contextErr error
	if executionErr == nil {
		measureCtx, stopMeasurement := context.WithCancel(callCtx)
		measurement := collectResourceUsage(measureCtx, id)
		executionErr = command.Wait()
		contextErr = callCtx.Err()
		result.FinishedAt = time.Now().UTC()
		stopMeasurement()
		result.ResourceUsage = <-measurement
	} else {
		contextErr = callCtx.Err()
		result.FinishedAt = time.Now().UTC()
	}
	result.Stdout, result.OutputTruncated = stdout.snapshot()
	var stderrTruncated bool
	result.Stderr, stderrTruncated = stderr.snapshot()
	result.OutputTruncated = result.OutputTruncated || stderrTruncated
	result.DurationMS = result.FinishedAt.Sub(result.StartedAt).Milliseconds()
	stateCtx, cancelState := context.WithTimeout(context.Background(), 5*time.Second)
	stateBody, stateErr := r.capture(stateCtx, "inspect", id)
	cancelState()
	state, stateKnown := parseStoppedContainerState(stateBody, id)
	stateKnown = stateKnown && stateErr == nil
	if stateKnown {
		result.ExitCode = state.ExitCode
	}
	switch {
	case result.OutputTruncated:
		result.Status = "output_limit"
		result.ErrorType = "OUTPUT_LIMIT"
	case ctx.Err() != nil:
		result.Status = "cancelled"
		result.ErrorType = "CANCELLED"
	case errors.Is(contextErr, context.DeadlineExceeded):
		result.Status = "timed_out"
		result.ErrorType = "TIME_LIMIT"
	case stateKnown && state.OOMKilled:
		result.Status = "resource_limit"
		result.ErrorType = "RESOURCE_LIMIT"
	case executionErr == nil && result.ExitCode == 0:
		result.Status = "succeeded"
	default:
		result.ErrorType = "CODE_EXITED"
	}
	return result, nil
}

type stoppedContainerState struct {
	ExitCode  *int
	OOMKilled *bool
	Running   *bool
}

// A caller-controlled exit code is not evidence of OOM or CPU exhaustion.
// Only a complete engine observation of this stopped container is authoritative.
func parseStoppedContainerState(body []byte, id string) (struct {
	ExitCode  int
	OOMKilled bool
}, bool) {
	var result struct {
		ExitCode  int
		OOMKilled bool
	}
	var rows []struct {
		ID    string `json:"Id"`
		State stoppedContainerState
	}
	if !containerID.MatchString(id) || json.Unmarshal(body, &rows) != nil || len(rows) != 1 || rows[0].ID != id {
		return result, false
	}
	s := rows[0].State
	if s.ExitCode == nil || s.OOMKilled == nil || s.Running == nil || *s.Running || *s.ExitCode < 0 || *s.ExitCode > 255 {
		return result, false
	}
	result.ExitCode, result.OOMKilled = *s.ExitCode, *s.OOMKilled
	return result, true
}

func (r *Runner) removeOwned(id, owner string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, err := r.capture(ctx, "inspect", id)
	if err != nil {
		// A successful bounded list proves absence; an inspect error alone does not.
		list, listErr := r.capture(ctx, "ps", "--all", "--filter", "label=agentplug.test.owner="+owner, "--format", "{{.ID}}")
		if listErr == nil && strings.TrimSpace(string(list)) == "" {
			return nil
		}
		return ErrCleanup
	}
	var rows []struct {
		Config struct{ Labels map[string]string }
	}
	if json.Unmarshal(body, &rows) != nil || len(rows) != 1 || rows[0].Config.Labels["agentplug.test.owner"] != owner || rows[0].Config.Labels["agentplug.code.controller"] != r.owner {
		return ErrCleanup
	}
	if _, err = r.capture(ctx, "rm", "--force", id); err != nil {
		return ErrCleanup
	}
	return nil
}

func (r *Runner) verifyIsolation(ctx context.Context, id, owner, language string, l Limits) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := r.capture(checkCtx, "inspect", id)
	if err != nil {
		return ErrUnavailable
	}
	var rows []struct {
		ID     string `json:"Id"`
		Image  string
		Config struct {
			User       string
			Labels     map[string]string
			WorkingDir string
			Entrypoint []string
			Cmd        []string
		}
		Mounts     []json.RawMessage
		HostConfig struct {
			Privileged     bool
			ReadonlyRootfs bool
			NetworkMode    string
			PidMode        string
			IpcMode        string
			CapAdd         []string
			CapDrop        []string
			SecurityOpt    []string
			Memory         int64
			MemorySwap     int64
			NanoCpus       int64
			PidsLimit      int64
			ShmSize        int64
			Ulimits        []struct {
				Name string
				Hard int64
				Soft int64
			}
			LogConfig     struct{ Type string }
			Tmpfs         map[string]string
			RestartPolicy struct{ Name string }
		}
	}
	if json.Unmarshal(body, &rows) != nil || len(rows) != 1 {
		return ErrUnavailable
	}
	row := rows[0]
	if row.ID != id || row.Image != r.images[language] || len(row.Config.Entrypoint) != 1 || row.Config.Entrypoint[0] != "/usr/local/bin/code-sandbox-guard" || len(row.Config.Cmd) != 1 || row.Config.Cmd[0] != language || row.Config.Labels["io.agentplug.code.filesystem-guard"] != "landlock-v3" || row.Config.Labels["io.agentplug.code.language"] != language {
		return ErrDenied
	}
	h := row.HostConfig
	profileMatched := false
	var compact bytes.Buffer
	if json.Compact(&compact, seccompProfile) != nil {
		return ErrDenied
	}
	for _, option := range h.SecurityOpt {
		if strings.HasPrefix(option, "seccomp=") {
			var actual bytes.Buffer
			if json.Compact(&actual, []byte(strings.TrimPrefix(option, "seccomp="))) == nil && bytes.Equal(actual.Bytes(), compact.Bytes()) {
				profileMatched = true
			}
		}
	}
	if !profileMatched {
		return ErrDenied
	}
	// Confirm daemon-enforced limits before starting untrusted code. CLI
	// arguments alone are not evidence that an engine applied those limits.
	expectedUlimits := map[string]int64{"cpu": int64(l.CPUSeconds), "fsize": l.DiskBytes, "nofile": 64}
	if len(h.Ulimits) != len(expectedUlimits) || h.ShmSize != 1<<20 {
		return ErrDenied
	}
	for _, limit := range h.Ulimits {
		expected, exists := expectedUlimits[limit.Name]
		if !exists || limit.Hard != expected || limit.Soft != expected {
			return ErrDenied
		}
		delete(expectedUlimits, limit.Name)
	}
	if row.Config.User != "65532:65532" || row.Config.WorkingDir != "/workspace" || row.Config.Labels["agentplug.test.owner"] != owner || row.Config.Labels["agentplug.code.controller"] != r.owner || len(row.Mounts) != 0 || h.Privileged || !h.ReadonlyRootfs || h.NetworkMode != "none" || h.PidMode != "" || h.IpcMode != "private" || len(h.CapAdd) != 0 || len(h.CapDrop) != 1 || strings.ToUpper(h.CapDrop[0]) != "ALL" || len(h.SecurityOpt) != 2 || !contains(h.SecurityOpt, "no-new-privileges:true") || h.Memory != l.MemoryBytes || h.MemorySwap != l.MemoryBytes || h.NanoCpus != int64(l.CPUMilli)*1000000 || h.PidsLimit != int64(l.PIDs) || h.LogConfig.Type != "none" || h.RestartPolicy.Name != "no" || len(h.Tmpfs) != 2 || h.Tmpfs["/workspace"] != fmt.Sprintf("rw,nosuid,nodev,noexec,size=%d,mode=1777", l.DiskBytes-(2<<20)) || h.Tmpfs["/tmp"] != "rw,nosuid,nodev,noexec,size=1048576,mode=1777" {
		return ErrDenied
	}
	return nil
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
