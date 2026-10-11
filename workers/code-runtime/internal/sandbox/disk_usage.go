package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	diskUsageSampleTimeout = 500 * time.Millisecond
	diskUsageOutputLimit   = 512
	diskUsageStatSource    = "docker_exec_tmpfs_stat/v1"
)

// readTmpfsAllocatedBytes runs only a fixed stat argv in the trusted
// controller-created container. The returned sum is allocated tmpfs blocks
// observed at one instant; it is not an execution-wide peak guarantee.
func readTmpfsAllocatedBytes(parent context.Context, client *http.Client, id, apiVersion string) (uint64, bool) {
	if parent == nil || client == nil || !containerID.MatchString(id) || !supportedEngineAPIVersion(apiVersion) {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(parent, diskUsageSampleTimeout)
	defer cancel()

	command := []string{"/bin/stat", "-f", "-c", "%b:%f:%S", "/workspace", "/tmp", "/dev/shm"}
	createBody, err := json.Marshal(map[string]any{
		"AttachStdin": false, "AttachStdout": true, "AttachStderr": true,
		"Tty": false, "Privileged": false, "User": "65532:65532",
		"WorkingDir": "/workspace", "Cmd": command,
	})
	if err != nil {
		return 0, false
	}
	createRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://localhost/v"+apiVersion+"/containers/"+id+"/exec", bytes.NewReader(createBody))
	if err != nil {
		return 0, false
	}
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse, err := client.Do(createRequest)
	if err != nil {
		return 0, false
	}
	createResponseBody, readErr := readBoundedResourceBody(createResponse.Body, 4096)
	_ = createResponse.Body.Close()
	if readErr != nil || createResponse.StatusCode != http.StatusCreated {
		return 0, false
	}
	var created struct {
		ID string `json:"Id"`
	}
	if json.Unmarshal(createResponseBody, &created) != nil || !containerID.MatchString(created.ID) {
		return 0, false
	}

	startBody := []byte(`{"Detach":false,"Tty":false}`)
	startRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://localhost/v"+apiVersion+"/exec/"+created.ID+"/start", bytes.NewReader(startBody))
	if err != nil {
		return 0, false
	}
	startRequest.Header.Set("Content-Type", "application/json")
	startResponse, err := client.Do(startRequest)
	if err != nil {
		return 0, false
	}
	if startResponse.StatusCode != http.StatusOK {
		_ = startResponse.Body.Close()
		return 0, false
	}
	stdout, streamOK := readDockerExecStream(startResponse.Body, diskUsageOutputLimit)
	closeErr := startResponse.Body.Close()
	if !streamOK || closeErr != nil || ctx.Err() != nil {
		return 0, false
	}

	inspectRequest, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost/v"+apiVersion+"/exec/"+created.ID+"/json", nil)
	if err != nil {
		return 0, false
	}
	inspectResponse, err := client.Do(inspectRequest)
	if err != nil {
		return 0, false
	}
	inspectBody, readErr := readBoundedResourceBody(inspectResponse.Body, 4096)
	_ = inspectResponse.Body.Close()
	if readErr != nil || inspectResponse.StatusCode != http.StatusOK {
		return 0, false
	}
	var inspected struct {
		ID          string `json:"ID"`
		ContainerID string `json:"ContainerID"`
		Running     *bool  `json:"Running"`
		ExitCode    *int   `json:"ExitCode"`
		Process     struct {
			Privileged *bool    `json:"privileged"`
			User       string   `json:"user"`
			TTY        *bool    `json:"tty"`
			Entrypoint string   `json:"entrypoint"`
			Arguments  []string `json:"arguments"`
		} `json:"ProcessConfig"`
	}
	if json.Unmarshal(inspectBody, &inspected) != nil || inspected.ID != created.ID || inspected.ContainerID != id ||
		inspected.Running == nil || *inspected.Running || inspected.ExitCode == nil || *inspected.ExitCode != 0 ||
		inspected.Process.Privileged == nil || *inspected.Process.Privileged || inspected.Process.User != "65532:65532" ||
		inspected.Process.TTY == nil || *inspected.Process.TTY || inspected.Process.Entrypoint != command[0] ||
		!equalStrings(inspected.Process.Arguments, command[1:]) {
		return 0, false
	}
	return parseTmpfsStatOutput(stdout)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func supportedEngineAPIVersion(version string) bool {
	switch version {
	case "1.41", "1.42", "1.43", "1.44", "1.45", "1.46", "1.47", "1.48":
		return true
	default:
		return false
	}
}

func readBoundedResourceBody(body io.ReadCloser, limit int) ([]byte, error) {
	if body == nil || limit < 0 {
		return nil, errors.New("resource response unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, errors.New("resource response exceeds limit")
	}
	return data, nil
}

// Docker's non-TTY exec stream is multiplexed into 8-byte framed stdout and
// stderr records. Stderr is discarded; neither stream contents nor paths are
// returned or logged.
func readDockerExecStream(reader io.Reader, limit int) ([]byte, bool) {
	if reader == nil || limit < 0 {
		return nil, false
	}
	stdout := make([]byte, 0, min(limit, 128))
	var total uint64
	frames := 0
	for {
		var header [8]byte
		_, err := io.ReadFull(reader, header[:])
		if errors.Is(err, io.EOF) {
			return stdout, true
		}
		frames++
		if err != nil || frames > 64 || (header[0] != 1 && header[0] != 2) || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return nil, false
		}
		length := binary.BigEndian.Uint32(header[4:])
		if uint64(length) > uint64(limit)-total {
			return nil, false
		}
		chunk := make([]byte, int(length))
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return nil, false
		}
		total += uint64(length)
		if header[0] == 1 {
			stdout = append(stdout, chunk...)
		}
	}
}

func parseTmpfsStatOutput(output []byte) (uint64, bool) {
	if len(output) == 0 || len(output) > diskUsageOutputLimit || strings.ContainsRune(string(output), '\x00') {
		return 0, false
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != 3 {
		return 0, false
	}
	var total uint64
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			return 0, false
		}
		blocks, okBlocks := parseStatUint(parts[0])
		free, okFree := parseStatUint(parts[1])
		blockSize, okSize := parseStatUint(parts[2])
		if !okBlocks || !okFree || !okSize || free > blocks || blockSize == 0 {
			return 0, false
		}
		usedBlocks := blocks - free
		if usedBlocks != 0 && blockSize > ^uint64(0)/usedBlocks {
			return 0, false
		}
		used := usedBlocks * blockSize
		if used >= 1<<53 || total >= (1<<53)-used {
			return 0, false
		}
		total += used
	}
	return total, true
}

func parseStatUint(value string) (uint64, bool) {
	if value == "" || len(value) > 20 {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil && parsed < 1<<53
}
