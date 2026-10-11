package coderuntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

// NormalizeResourceUsage accepts only bounded measurement metadata, never
// arbitrary controller output or environment values destined for audit logs.
// A legacy receipt with no sampling provenance remains explicitly unknown.
func NormalizeResourceUsage(raw map[string]any) (map[string]any, error) {
	unknown := map[string]any{"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil,
		"sampled_peak_memory_bytes": nil, "sample_count": 0,
		"measurement_source": "unavailable", "measurement_complete": false,
		"disk_sample_count": 0, "disk_measurement_source": "unavailable"}
	if len(raw) == 0 {
		return unknown, nil
	}
	allowed := map[string]bool{"cpu_time_ms": true, "peak_memory_bytes": true, "disk_bytes": true,
		"sampled_peak_memory_bytes": true, "sample_count": true,
		"measurement_source": true, "measurement_complete": true,
		"disk_sample_count": true, "disk_measurement_source": true}
	invalid := errors.New("invalid code resource measurement")
	for key := range raw {
		if !allowed[key] {
			return nil, invalid
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 4096 {
		return nil, invalid
	}
	var values map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&values) != nil {
		return nil, invalid
	}
	if _, exists := values["measurement_source"]; !exists {
		// The earlier controller reported only these three null measurements.
		if len(values) != 3 {
			return nil, invalid
		}
		for key, value := range values {
			if (key != "cpu_time_ms" && key != "peak_memory_bytes" && key != "disk_bytes") || value != nil {
				return nil, invalid
			}
		}
		return unknown, nil
	}
	// A previous controller emitted seven provenance fields but no disk
	// sampler. Accept only its explicit null disk value and normalize the new
	// source/count pair to unavailable; partial new metadata is rejected.
	if _, hasDiskCount := values["disk_sample_count"]; !hasDiskCount {
		if _, hasDiskSource := values["disk_measurement_source"]; hasDiskSource || len(values) != len(allowed)-2 || values["disk_bytes"] != nil {
			return nil, invalid
		}
		values["disk_sample_count"] = json.Number("0")
		values["disk_measurement_source"] = "unavailable"
	}
	if len(values) != len(allowed) || values["measurement_complete"] != false {
		return nil, invalid
	}
	source, ok := values["measurement_source"].(string)
	if !ok || (source != "unavailable" && source != "docker_engine_sampled/v1") {
		return nil, invalid
	}
	count, ok := measurementUint(values["sample_count"])
	if !ok || count > 128 || (source == "unavailable") != (count == 0) {
		return nil, invalid
	}
	diskSource, ok := values["disk_measurement_source"].(string)
	if !ok || (diskSource != "unavailable" && diskSource != "docker_exec_tmpfs_stat/v1") {
		return nil, invalid
	}
	diskCount, ok := measurementUint(values["disk_sample_count"])
	if !ok || diskCount > 128 || (diskSource == "unavailable") != (diskCount == 0) {
		return nil, invalid
	}
	for _, key := range []string{"cpu_time_ms", "peak_memory_bytes", "sampled_peak_memory_bytes"} {
		value := values[key]
		if value == nil {
			continue
		}
		if _, valid := measurementUint(value); !valid || source == "unavailable" {
			return nil, invalid
		}
	}
	if values["disk_bytes"] != nil {
		if _, valid := measurementUint(values["disk_bytes"]); !valid || diskSource == "unavailable" {
			return nil, invalid
		}
	}
	if source == "unavailable" {
		if values["cpu_time_ms"] != nil || values["peak_memory_bytes"] != nil || values["sampled_peak_memory_bytes"] != nil {
			return nil, invalid
		}
	} else if values["cpu_time_ms"] == nil || values["sampled_peak_memory_bytes"] == nil {
		return nil, invalid
	}
	if (diskSource == "unavailable" && values["disk_bytes"] != nil) ||
		(diskSource == "docker_exec_tmpfs_stat/v1" && values["disk_bytes"] == nil) {
		return nil, invalid
	}
	return values, nil
}

func measurementUint(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	return parsed, err == nil && parsed < 1<<53
}
