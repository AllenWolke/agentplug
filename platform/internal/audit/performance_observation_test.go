package audit

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func performanceFixtureScope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", AgentID: "agent", AgentInstanceID: "instance",
		PrincipalID: "user", PrincipalType: "user", InstallationID: "installation", AgentVersionID: "version", SessionID: "session",
		RunID: "run", AuthorizationEpoch: 1, TraceID: "trace"}
}

func performanceFixture(s sharedkernel.Scope) PerformanceObservation {
	start := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	o := NewPerformanceObservation(s, "PRIVATE-IDEMPOTENCY-KEY", "knowledge_query", "succeeded", start, start.Add(43*time.Millisecond))
	l, h, f := int64(4), int64(3), int64(0)
	o.CacheMode, o.CacheLookups, o.CacheHits, o.CacheFailures = "use", &l, &h, &f
	return o
}

func TestHistoricalWallDurationMismatchIsClassifiedWithoutRepairOrIdentityBypass(t *testing.T) {
	s := performanceFixtureScope()
	o := performanceFixture(s)
	// Reproduce the real retained receipt: 9ms elapsed versus 7.466113ms
	// wall interval after the Go monotonic component has been serialized away.
	o.StartedAt, _ = time.Parse(time.RFC3339Nano, "2026-10-14T03:39:44.592886612Z")
	o.FinishedAt, _ = time.Parse(time.RFC3339Nano, "2026-10-14T03:39:44.600352725Z")
	o.DurationMS = 9
	before, _ := json.Marshal(o)
	if o.Validate(s) == nil || !o.HasInconsistentWallDuration(s) {
		t.Fatal("historical timing mismatch was accepted or not classified")
	}
	after, _ := json.Marshal(o)
	if string(before) != string(after) {
		t.Fatal("historical timing was rewritten")
	}
	foreign := s
	foreign.PrincipalID = "another-user"
	if o.HasInconsistentWallDuration(foreign) {
		t.Fatal("foreign identity bypassed strict validation")
	}
	for _, change := range []func(*PerformanceObservation){
		func(v *PerformanceObservation) { v.Status = "invented" },
		func(v *PerformanceObservation) { v.DurationMS = -1 },
		func(v *PerformanceObservation) { v.FinishedAt = v.StartedAt.Add(-time.Second) },
		func(v *PerformanceObservation) { v.TimingSource = "vendor_claim" },
		func(v *PerformanceObservation) { v.CacheHits = nil },
	} {
		invalid := o
		change(&invalid)
		if invalid.HasInconsistentWallDuration(s) {
			t.Fatal("non-duration corruption was hidden")
		}
	}
	valid := performanceFixture(s)
	if valid.HasInconsistentWallDuration(s) {
		t.Fatal("valid timing was marked missing")
	}
}

func TestPerformanceObservationIsClosedAndPreservesMeasuredIdentity(t *testing.T) {
	s := performanceFixtureScope()
	o := performanceFixture(s)
	if err := o.validate(s); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(o)
	if strings.Contains(string(raw), "PRIVATE-IDEMPOTENCY-KEY") {
		t.Fatal("raw request key leaked")
	}
	if _, err := decodePerformanceObservation(string(raw), s); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{strings.TrimSuffix(string(raw), "}") + `,"prompt":"private input"}`, string(raw) + ` {}`, strings.Repeat("x", 4097)} {
		if _, err := decodePerformanceObservation(raw, s); err == nil {
			t.Fatal("invalid/unbounded performance payload was accepted")
		}
	}
	// Current epoch renewal preserves the identity of historical measurements.
	renewed := s
	renewed.AuthorizationEpoch++
	if err := o.validate(renewed); err != nil {
		t.Fatal(err)
	}
}

func TestPerformanceObservationCannotCrossExecutionIdentity(t *testing.T) {
	s := performanceFixtureScope()
	o := performanceFixture(s)
	for _, field := range []string{"tenant", "department", "application", "agent", "instance", "principal", "installation", "version", "session", "run", "parent"} {
		t.Run(field, func(t *testing.T) {
			other := s
			switch field {
			case "tenant":
				other.TenantID += "-foreign"
			case "department":
				other.DepartmentID += "-foreign"
			case "application":
				other.ApplicationID += "-foreign"
			case "agent":
				other.AgentID += "-foreign"
			case "instance":
				other.AgentInstanceID += "-foreign"
			case "principal":
				other.PrincipalID += "-foreign"
			case "installation":
				other.InstallationID += "-foreign"
			case "version":
				other.AgentVersionID += "-foreign"
			case "session":
				other.SessionID += "-foreign"
			case "run":
				other.RunID += "-foreign"
			case "parent":
				other.ParentRunID = "foreign-parent"
			}
			if o.validate(other) == nil {
				t.Fatal("performance metadata crossed identity")
			}
		})
	}
}

func TestPerformanceObservationRejectsInventedOrOverflowedMeasurements(t *testing.T) {
	s := performanceFixtureScope()
	for _, kind := range []string{"negative-duration", "inconsistent-duration", "unknown-source", "unknown-status", "negative-hits", "hits-overflow", "failures-overflow", "sum-overflow", "missing-counts", "foreign-kind"} {
		t.Run(kind, func(t *testing.T) {
			o := performanceFixture(s)
			switch kind {
			case "negative-duration":
				o.DurationMS = -1
			case "inconsistent-duration":
				o.DurationMS++
			case "unknown-source":
				o.TimingSource = "vendor_claim"
			case "unknown-status":
				o.Status = "complete-with-private-error"
			case "negative-hits":
				*o.CacheHits = -1
			case "hits-overflow":
				*o.CacheHits = math.MaxInt64
			case "failures-overflow":
				*o.CacheFailures = math.MaxInt64
			case "sum-overflow":
				*o.CacheHits = math.MaxInt64
				*o.CacheFailures = math.MaxInt64
			case "missing-counts":
				o.CacheHits = nil
			case "foreign-kind":
				o.Kind = "arbitrary tool input"
			}
			if o.validate(s) == nil {
				t.Fatal("invented measurement accepted")
			}
		})
	}
}
