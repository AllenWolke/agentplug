package coderuntime

import (
	"encoding/json"
	"testing"
)

func TestResourceMeasurementsRemainUnknownWithoutProvenance(t *testing.T) {
	for _, raw := range []map[string]any{nil, {"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil}} {
		usage, err := NormalizeResourceUsage(raw)
		if err != nil || usage["cpu_time_ms"] != nil || usage["measurement_source"] != "unavailable" || usage["measurement_complete"] != false {
			t.Fatal("unknown measurement became a recorded value", err)
		}
	}
	if _, err := NormalizeResourceUsage(map[string]any{"cpu_time_ms": nil}); err == nil {
		t.Fatal("partial legacy receipt was accepted")
	}
}

func TestResourceMeasurementsRejectSecretsInventedDiskAndCompleteClaims(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{
			"cpu_time_ms": 12, "peak_memory_bytes": nil, "disk_bytes": nil,
			"sampled_peak_memory_bytes": 1024, "sample_count": 1,
			"measurement_source": "docker_engine_sampled/v1", "measurement_complete": false,
		}
	}
	if _, err := NormalizeResourceUsage(valid()); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(map[string]any){
		func(v map[string]any) { v["environment"] = "secret" },
		func(v map[string]any) { v["disk_bytes"] = 1024 },
		func(v map[string]any) { v["measurement_complete"] = true },
		func(v map[string]any) { v["cpu_time_ms"] = -1 },
		func(v map[string]any) { v["cpu_time_ms"] = 1.5 },
		func(v map[string]any) { v["sample_count"] = 129 },
	} {
		v := valid()
		mutation(v)
		if _, err := NormalizeResourceUsage(v); err == nil {
			t.Fatal("invalid audit measurement accepted")
		}
	}
}

func TestTmpfsDiskMeasurementsRequireMatchingProvenanceAndBounds(t *testing.T) {
	raw := map[string]any{
		"cpu_time_ms": 12, "peak_memory_bytes": nil, "disk_bytes": 4096,
		"sampled_peak_memory_bytes": 1024, "sample_count": 1,
		"measurement_source": "docker_engine_sampled/v1", "measurement_complete": false,
		"disk_sample_count": 2, "disk_measurement_source": "docker_exec_tmpfs_stat/v1",
	}
	if _, err := NormalizeResourceUsage(raw); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(map[string]any){
		func(v map[string]any) { v["disk_sample_count"] = 0 },
		func(v map[string]any) { v["disk_sample_count"] = 129 },
		func(v map[string]any) { v["disk_measurement_source"] = "controller_input" },
		func(v map[string]any) { v["disk_bytes"] = uint64(1 << 53) },
		func(v map[string]any) { delete(v, "disk_sample_count") },
	} {
		candidate := make(map[string]any, len(raw))
		for key, value := range raw {
			candidate[key] = value
		}
		mutation(candidate)
		if _, err := NormalizeResourceUsage(candidate); err == nil {
			t.Fatal("invalid disk provenance accepted")
		}
	}
}

func TestTmpfsMeasurementCanSucceedWhenEngineCPUStatsAreUnavailable(t *testing.T) {
	usage, err := NormalizeResourceUsage(map[string]any{
		"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": 4096,
		"sampled_peak_memory_bytes": nil, "sample_count": 0,
		"measurement_source": "unavailable", "measurement_complete": false,
		"disk_sample_count": 1, "disk_measurement_source": "docker_exec_tmpfs_stat/v1",
	})
	if err != nil || usage["disk_bytes"] != json.Number("4096") || usage["cpu_time_ms"] != nil {
		t.Fatal("independent disk sample was rejected or invented CPU usage", err, usage)
	}
}
