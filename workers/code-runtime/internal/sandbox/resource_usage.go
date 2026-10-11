package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Only the trusted controller reads engine metrics. The socket, container ID
// and endpoint cannot be selected by submitted code or caller input.
type engineResourceSample struct {
	ID   string    `json:"id"`
	Read time.Time `json:"read"`
	CPU  struct {
		Usage struct {
			Total *uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
	} `json:"cpu_stats"`
	Memory struct {
		Usage   *uint64 `json:"usage"`
		Maximum uint64  `json:"max_usage"`
	} `json:"memory_stats"`
}

func unknownResourceUsage() map[string]any {
	return map[string]any{"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil,
		"sampled_peak_memory_bytes": nil, "sample_count": 0,
		"measurement_source": "unavailable", "measurement_complete": false,
		"disk_sample_count": 0, "disk_measurement_source": "unavailable"}
}

// Sampling is advisory and never changes sandbox permissions or completion.
// Values describe observed samples, not proof of a whole-execution maximum.
// In particular, neither configured limits nor block IO bytes are disk usage.
func collectResourceUsage(ctx context.Context, id string) <-chan map[string]any {
	completed := make(chan map[string]any, 1)
	if runtime.GOOS != "linux" || !containerID.MatchString(id) {
		completed <- unknownResourceUsage()
		return completed
	}
	go func() {
		usage := unknownResourceUsage()
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "unix", "/var/run/docker.sock")
			}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 750 * time.Millisecond,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		apiVersion, ok := engineStatisticsAPIVersion(ctx, client)
		if !ok {
			completed <- usage
			return
		}
		var cpu, memory, peak, diskPeak uint64
		var lastRead time.Time
		count, diskCount := 0, 0
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for attempts := 0; attempts < 128 && ctx.Err() == nil; attempts++ {
			if sample, ok := readEngineResourceSample(ctx, client, id, apiVersion); ok && sample.Read.After(lastRead) {
				lastRead = sample.Read
				count++
				cpu = max(cpu, *sample.CPU.Usage.Total)
				memory = max(memory, *sample.Memory.Usage)
				peak = max(peak, sample.Memory.Maximum)
			}
			if used, ok := readTmpfsAllocatedBytes(ctx, client, id, apiVersion); ok {
				diskPeak = max(diskPeak, used)
				diskCount++
			}
			select {
			case <-ctx.Done():
			case <-ticker.C:
			}
		}
		if count != 0 {
			usage["cpu_time_ms"] = cpu / uint64(time.Millisecond)
			usage["sampled_peak_memory_bytes"] = memory
			if peak != 0 {
				usage["peak_memory_bytes"] = peak
			}
			usage["sample_count"] = count
			usage["measurement_source"] = "docker_engine_sampled/v1"
		}
		if diskCount != 0 {
			usage["disk_bytes"] = diskPeak
			usage["disk_sample_count"] = diskCount
			usage["disk_measurement_source"] = diskUsageStatSource
		}
		completed <- usage
	}()
	return completed
}

func engineStatisticsAPIVersion(ctx context.Context, client *http.Client) (string, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/version", nil)
	if err != nil {
		return "", false
	}
	response, err := client.Do(request)
	if err != nil {
		return "", false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var version struct {
		API     string `json:"ApiVersion"`
		Minimum string `json:"MinAPIVersion"`
	}
	if err != nil || len(body) > 4096 || json.Unmarshal(body, &version) != nil {
		return "", false
	}
	parse := func(value string) (int, bool) {
		parts := strings.Split(value, ".")
		if len(parts) != 2 || parts[0] != "1" || len(parts[1]) != 2 {
			return 0, false
		}
		minor, err := strconv.Atoi(parts[1])
		return minor, err == nil
	}
	server, ok := parse(version.API)
	minimum, minimumOK := parse(version.Minimum)
	if !ok || !minimumOK || server < 41 || minimum > server {
		return "", false
	}
	// This reader knows the v1.48 stats shape and requires one-shot support.
	selected := min(server, 48)
	if selected < minimum {
		return "", false
	}
	return "1." + strconv.Itoa(selected), true
}

func readEngineResourceSample(ctx context.Context, client *http.Client, id, apiVersion string) (engineResourceSample, bool) {
	var sample engineResourceSample
	if !containerID.MatchString(id) || (apiVersion != "1.41" && apiVersion != "1.42" && apiVersion != "1.43" && apiVersion != "1.44" && apiVersion != "1.45" && apiVersion != "1.46" && apiVersion != "1.47" && apiVersion != "1.48") {
		return sample, false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost/v"+apiVersion+"/containers/"+id+"/stats?stream=false&one-shot=true", nil)
	if err != nil {
		return sample, false
	}
	response, err := client.Do(request)
	if err != nil {
		return sample, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return sample, false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if err != nil || len(body) > 256<<10 || json.Unmarshal(body, &sample) != nil ||
		sample.ID != id || sample.Read.IsZero() || sample.CPU.Usage.Total == nil || sample.Memory.Usage == nil ||
		*sample.CPU.Usage.Total >= 1<<53 || *sample.Memory.Usage >= 1<<53 || sample.Memory.Maximum >= 1<<53 {
		return engineResourceSample{}, false
	}
	return sample, true
}
