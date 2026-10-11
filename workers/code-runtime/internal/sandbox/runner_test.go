package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func testLimits() Limits {
	return Limits{MemoryBytes: 128 << 20, CPUMilli: 500, CPUSeconds: 2, PIDs: 32, DiskBytes: 6 << 20, TimeoutSeconds: 10, OutputBytes: 64 << 10}
}
func liveRunner(t *testing.T) *Runner {
	t.Helper()
	raw := os.Getenv("AGENTPLUG_CODE_RUNTIME_TEST_IMAGES")
	if raw == "" {
		t.Skip("explicit owned Docker fixture required")
	}
	images := map[string]string{}
	if json.Unmarshal([]byte(raw), &images) != nil {
		t.Fatal("invalid pinned fixture images")
	}
	r, err := New(Config{Owner: os.Getenv("AGENTPLUG_CODE_RUNTIME_TEST_OWNER"), Images: images, MaxConcurrent: 2, DockerConfigDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func runCode(t *testing.T, r *Runner, language, code string) Result {
	t.Helper()
	result, err := r.Run(context.Background(), Request{Language: language, Code: code, Limits: testLimits()})
	if err != nil {
		t.Fatal("isolated execution or cleanup failed", err)
	}
	if result.Version != "code-execution/v1" || !result.ContainerRemoved || result.DurationMS < 0 {
		t.Fatal("missing finalized cleanup/result contract")
	}
	return result
}

func TestCodeRuntimeValidatesLimitsBeforeLaunching(t *testing.T) {
	r := &Runner{images: map[string]string{"python": "sha256:" + strings.Repeat("a", 64)}, slots: make(chan struct{}, 1)}
	for _, change := range []func(*Request){func(q *Request) { q.Language = "host-shell" }, func(q *Request) { q.Code = "" }, func(q *Request) { q.Code = strings.Repeat("x", 65537) }, func(q *Request) { q.Limits.MemoryBytes = 0 }, func(q *Request) { q.Limits.CPUMilli = 2000 }, func(q *Request) { q.Limits.PIDs = 0 }, func(q *Request) { q.Limits.DiskBytes = 1 }, func(q *Request) { q.Limits.TimeoutSeconds = 61 }, func(q *Request) { q.Limits.OutputBytes = 1024 }} {
		q := Request{Language: "python", Code: "print(1)", Limits: testLimits()}
		change(&q)
		if _, err := r.Run(context.Background(), q); !errors.Is(err, ErrDenied) {
			t.Fatal("unsafe request accepted")
		}
	}
	r.slots <- struct{}{}
	if _, err := r.Run(context.Background(), Request{Language: "python", Code: "print(1)", Limits: testLimits()}); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded queue admitted")
	}
}

func TestCodeRuntimeActualThreeLanguagesAndStreamCapture(t *testing.T) {
	r := liveRunner(t)
	for _, entry := range []struct{ language, code string }{
		{"python", "import sys\nprint('runtime-ok')\nprint('runtime-stderr',file=sys.stderr)\n"},
		{"javascript", "console.log('runtime-ok');console.error('runtime-stderr');\n"},
		{"shell", "printf 'runtime-ok\\n'; printf 'runtime-stderr\\n' >&2\n"},
	} {
		t.Run(entry.language, func(t *testing.T) {
			result := runCode(t, r, entry.language, entry.code)
			if result.Status != "succeeded" || !strings.Contains(result.Stdout, "runtime-ok") || !strings.Contains(result.Stderr, "runtime-stderr") {
				t.Fatalf("language/stream contract failed status=%s error=%s exit=%d stderr=%.512q", result.Status, result.ErrorType, result.ExitCode, result.Stderr)
			}
		})
	}
}

func TestCodeRuntimeActualKernelPathGuardRejectsTraversalLinksAndDescriptors(t *testing.T) {
	r := liveRunner(t)
	code := `import os
for path in ['/etc/passwd','/proc/self/environ','/proc/self/fd/3','/workspace/../etc/passwd']:
 try:
  open(path,'rb').read(1)
  raise AssertionError('disallowed read succeeded')
 except OSError: pass
os.symlink('/etc', '/workspace/forbidden-link')
try:
 open('/workspace/forbidden-link/passwd').read(1)
 raise AssertionError('symlink escaped permission guard')
except OSError: pass
directory = os.open('/workspace', os.O_RDONLY | os.O_DIRECTORY)
try:
 try:
  os.open('../etc/passwd', os.O_RDONLY, dir_fd=directory)
  raise AssertionError('directory descriptor escaped permission guard')
 except OSError: pass
finally: os.close(directory)
for directory in ['/workspace','/tmp','/dev/shm']:
 path=directory+'/guard-allowed.txt'
 with open(path,'w') as f: f.write('allowed')
 with open(path) as f: assert f.read()=='allowed'
 os.truncate(path,0)
 os.unlink(path)
print('kernel-path-guard-ok')
`
	result := runCode(t, r, "python", code)
	if result.Status != "succeeded" || !strings.Contains(result.Stdout, "kernel-path-guard-ok") {
		t.Fatal("kernel filesystem guard did not enforce actual path boundaries", result.Status, result.ErrorType)
	}
}

func TestCodeRuntimeActualFilesystemNetworkCredentialsAndJobIsolation(t *testing.T) {
	r := liveRunner(t)
	t.Setenv("DEEPSEEK_API_KEY", "synthetic-controller-only-secret")
	code := `import os,socket
assert os.getuid()==65532
try:
 open('/proc/self/status').read()
 raise RuntimeError('proc read succeeded')
except PermissionError: pass
assert 'DEEPSEEK_API_KEY' not in os.environ
assert not os.path.exists('/var/run/docker.sock')
assert not os.path.exists('/run/secrets/model-providers')
for path in ['/etc/agentplug-write-test','/outside-workspace']:
 try:
  open(path,'w').write('blocked')
  raise RuntimeError('root write succeeded')
 except OSError: pass
try:
 socket.socket()
 raise RuntimeError('network socket creation succeeded')
except PermissionError: pass
open('/workspace/marker','w').write('private')
print('isolation-ok')
`
	first := runCode(t, r, "python", code)
	if first.Status != "succeeded" || !strings.Contains(first.Stdout, "isolation-ok") {
		t.Fatal("isolation failed", first.Status, first.Stderr)
	}
	second := runCode(t, r, "python", "import os\nassert not os.path.exists('/workspace/marker')\nprint('fresh-workspace')\n")
	if second.Status != "succeeded" || !strings.Contains(second.Stdout, "fresh-workspace") {
		t.Fatal("workspace crossed jobs")
	}
}

func TestCodeRuntimeActualDiskPIDsAndMemoryLimits(t *testing.T) {
	r := liveRunner(t)
	disk := runCode(t, r, "python", `import errno
try:
 open('/workspace/a','wb').write(b'a'*(3<<20))
 open('/workspace/b','wb').write(b'b'*(3<<20))
 raise RuntimeError('disk limit absent')
except OSError as e:
 assert e.errno in (errno.ENOSPC,errno.EFBIG)
 print('disk-limit-ok')
`)
	if disk.Status != "succeeded" || !strings.Contains(disk.Stdout, "disk-limit-ok") {
		t.Fatal("aggregate disk bound failed", disk.Status, disk.Stderr)
	}
	pids := runCode(t, r, "python", `import os,time,errno
children=[];blocked=False
for n in range(128):
 try:
  child=os.fork()
 except OSError as e:
  assert e.errno==errno.EAGAIN
  blocked=True;break
 if child==0:
  time.sleep(0.5);os._exit(0)
 children.append(child)
for child in children: os.waitpid(child,0)
assert blocked
print('pids-limit-ok')
`)
	if pids.Status != "succeeded" || !strings.Contains(pids.Stdout, "pids-limit-ok") {
		t.Fatal("PID limit absent", pids.Status, pids.Stderr)
	}
	memory := runCode(t, r, "python", "data=bytearray(300<<20)\nprint('memory-limit-absent')\n")
	if memory.Status != "resource_limit" || strings.Contains(memory.Stdout, "memory-limit-absent") {
		t.Fatal("memory bound not enforced", memory.Status, memory.ErrorType)
	}
}

func TestCodeRuntimeActualCPUTimeoutCancellationAndOutputLimits(t *testing.T) {
	r := liveRunner(t)
	cpu := runCode(t, r, "python", "while True: pass\n")
	// Linux's CPU hard limit can kill with SIGKILL, but exit code 137 alone
	// cannot distinguish that from an intentional exit. Assert enforcement
	// without manufacturing an OOM diagnosis from an ambiguous exit code.
	if cpu.Status != "failed" || cpu.ErrorType != "CODE_EXITED" || cpu.ExitCode != 137 || cpu.DurationMS > 9000 {
		t.Fatal("CPU hard limit not enforced", cpu.Status, cpu.DurationMS)
	}
	timeout := runCode(t, r, "python", "import time\ntime.sleep(60)\n")
	if timeout.Status != "timed_out" || timeout.DurationMS > 15000 {
		t.Fatal("wall time not enforced", timeout.Status, timeout.DurationMS)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cancelled, err := r.Run(ctx, Request{Language: "python", Code: "import time\ntime.sleep(60)\n", Limits: testLimits()})
	if err != nil || cancelled.Status != "cancelled" || !cancelled.ContainerRemoved {
		t.Fatal("cancel did not terminate/clean sandbox", cancelled.Status, err)
	}
	output := runCode(t, r, "python", "import sys\nsys.stdout.write('x'*(2<<20))\nsys.stdout.flush()\n")
	if output.Status != "output_limit" || len(output.Stdout) > 64<<10 || !output.OutputTruncated {
		t.Fatal("stdout retained beyond budget", output.Status, len(output.Stdout))
	}
	stderr := runCode(t, r, "python", "import sys\nsys.stderr.write('x'*(2<<20))\nsys.stderr.flush()\n")
	if stderr.Status != "output_limit" || len(stderr.Stderr) > 64<<10 || !stderr.OutputTruncated {
		t.Fatal("stderr retained beyond budget", stderr.Status, len(stderr.Stderr))
	}
}

func TestCodeRuntimeIntentionalExitIsNotResourceEvidence(t *testing.T) {
	r := liveRunner(t)
	for _, entry := range []struct{ language, code string }{
		{"python", "import sys\nsys.exit(137)\n"},
		{"javascript", "process.exit(137);\n"},
		{"shell", "exit 137\n"},
	} {
		t.Run(entry.language, func(t *testing.T) {
			result := runCode(t, r, entry.language, entry.code)
			if result.Status != "failed" || result.ErrorType != "CODE_EXITED" || result.ExitCode != 137 {
				t.Fatal("intentional exit misclassified as a resource measurement", result.Status, result.ErrorType)
			}
		})
	}
}

func TestStoppedContainerStateRequiresCompleteMatchingEngineEvidence(t *testing.T) {
	id := strings.Repeat("a", 64)
	valid := `[{"Id":"` + id + `","State":{"ExitCode":137,"OOMKilled":false,"Running":false}}]`
	state, ok := parseStoppedContainerState([]byte(valid), id)
	if !ok || state.ExitCode != 137 || state.OOMKilled {
		t.Fatal("real non-OOM exit observation lost")
	}
	for _, body := range []string{
		strings.Replace(valid, id, strings.Repeat("b", 64), 1),
		strings.Replace(valid, `"Running":false`, `"Running":true`, 1),
		strings.Replace(valid, `"OOMKilled":false,`, "", 1),
		strings.Replace(valid, `"ExitCode":137`, `"ExitCode":256`, 1),
		valid + "trailing",
	} {
		if _, ok := parseStoppedContainerState([]byte(body), id); ok {
			t.Fatal("incomplete or unrelated engine observation accepted")
		}
	}
}
