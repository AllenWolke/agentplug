package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
)

// Explicit model deadlines remain bounded; tool and sandbox limits are independent.
func governedModelHTTPConfig(secretRoot string, development bool) (modelgateway.HTTPConfig, error) {
	config := modelgateway.HTTPConfig{SecretRoot: secretRoot, AllowLoopbackDevelopment: development}
	duration := func(name string, fallback int) (time.Duration, error) {
		raw := strings.TrimSpace(os.Getenv(name))
		seconds := fallback
		if raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 300 {
				return 0, fmt.Errorf("%s must be an integer between 1 and 300 seconds", name)
			}
			seconds = parsed
		}
		return time.Duration(seconds) * time.Second, nil
	}
	var err error
	config.RequestTimeout, err = duration("PLATFORM_MODEL_REQUEST_TIMEOUT_SECONDS", 30)
	if err != nil {
		return modelgateway.HTTPConfig{}, err
	}
	config.ResponseHeaderTimeout, err = duration("PLATFORM_MODEL_RESPONSE_HEADER_TIMEOUT_SECONDS", 10)
	if err != nil {
		return modelgateway.HTTPConfig{}, err
	}
	if config.ResponseHeaderTimeout > config.RequestTimeout {
		return modelgateway.HTTPConfig{}, fmt.Errorf("model response-header deadline must not exceed request deadline")
	}
	if raw := strings.TrimSpace(os.Getenv("PLATFORM_MODEL_DNS_OVER_HTTPS_HOSTS_JSON")); raw != "" {
		var hosts []string
		if len(raw) > 4096 || json.Unmarshal([]byte(raw), &hosts) != nil || hosts == nil {
			return modelgateway.HTTPConfig{}, fmt.Errorf("invalid model HTTPS DNS host configuration")
		}
		if len(hosts) > 0 {
			config.Resolver, err = modelgateway.NewGoogleDoHResolver(hosts)
			if err != nil {
				return modelgateway.HTTPConfig{}, fmt.Errorf("invalid model HTTPS DNS host configuration")
			}
		}
	}
	return config, nil
}
