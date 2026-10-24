package main

import (
	"strings"
	"testing"
	"time"
)

func TestGovernedModelDeadlineConfiguration(t *testing.T) {
	t.Setenv("PLATFORM_MODEL_DNS_OVER_HTTPS_HOSTS_JSON", "")
	for _, item := range []struct {
		name, request, header         string
		valid                         bool
		requestSeconds, headerSeconds int
	}{
		{"defaults", "", "", true, 30, 10},
		{"thinking_model", "180", "150", true, 180, 150},
		{"small", "2", "1", true, 2, 1},
		{"maximum", "300", "300", true, 300, 300},
		{"zero", "0", "1", false, 0, 0},
		{"negative", "-1", "1", false, 0, 0},
		{"unbounded", "301", "10", false, 0, 0},
		{"nan", "NaN", "10", false, 0, 0},
		{"fraction", "1.5", "1", false, 0, 0},
		{"private_value", "private-credential", "10", false, 0, 0},
		{"header_above_request", "10", "11", false, 0, 0},
		{"header_invalid", "180", "Infinity", false, 0, 0},
	} {
		t.Run(item.name, func(t *testing.T) {
			t.Setenv("PLATFORM_MODEL_REQUEST_TIMEOUT_SECONDS", item.request)
			t.Setenv("PLATFORM_MODEL_RESPONSE_HEADER_TIMEOUT_SECONDS", item.header)
			result, err := governedModelHTTPConfig("/protected-provider-root", false)
			if (err == nil) != item.valid {
				t.Fatalf("validity mismatch: %v", err)
			}
			if err != nil {
				if strings.Contains(err.Error(), "private-credential") {
					t.Fatal("invalid input was exposed")
				}
				return
			}
			if result.RequestTimeout != time.Duration(item.requestSeconds)*time.Second || result.ResponseHeaderTimeout != time.Duration(item.headerSeconds)*time.Second || result.SecretRoot != "/protected-provider-root" || result.AllowLoopbackDevelopment {
				t.Fatal("deadline or credential boundary changed")
			}
		})
	}
}

func TestGovernedModelHTTPSDNSIsExplicitAndBounded(t *testing.T) {
	t.Setenv("PLATFORM_MODEL_REQUEST_TIMEOUT_SECONDS", "")
	t.Setenv("PLATFORM_MODEL_RESPONSE_HEADER_TIMEOUT_SECONDS", "")
	for _, test := range []struct {
		raw            string
		valid, enabled bool
	}{
		{"", true, false}, {"[]", true, false}, {`["api.example"]`, true, true},
		{"null", false, false}, {`[null]`, false, false}, {`{}`, false, false}, {`["localhost"]`, false, false},
		{`["private-credential"]`, false, false}, {`["api.example","api.example"]`, false, false},
		{strings.Repeat("x", 4097), false, false},
	} {
		t.Setenv("PLATFORM_MODEL_DNS_OVER_HTTPS_HOSTS_JSON", test.raw)
		config, err := governedModelHTTPConfig("/protected", false)
		if (err == nil) != test.valid || err == nil && (config.Resolver != nil) != test.enabled {
			t.Fatalf("unexpected resolver configuration: %v", err)
		}
		if err != nil && strings.Contains(err.Error(), "private-credential") {
			t.Fatal("operator configuration leaked")
		}
	}
}
