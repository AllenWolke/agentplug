package evaluationproduct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	agenteval "github.com/lexagent/agent-evaluation"
)

type profileInspection struct {
	calls               int
	profile, projection string
	err                 error
}

func (p *profileInspection) Agents(context.Context, Actor, int, int) (agenteval.Discovery, error) {
	return agenteval.Discovery{}, p.err
}

func (p *profileInspection) Trajectory(ctx context.Context, actor Actor, id, session string, revision uint64) (agenteval.Trajectory, error) {
	p.calls++
	p.profile, p.projection = EvidenceReadProfile(ctx), ToolArgumentProjection(ctx)
	if actor.PrincipalID != "owner" || session != "current-session" || revision != 1 {
		return agenteval.Trajectory{}, ErrForbidden
	}
	return agenteval.Trajectory{RunID: id, EvidenceReadProfile: p.profile, ToolArgumentProjection: p.projection}, p.err
}

func TestTrajectoryReadProfileIsExplicitBoundedAndStillAuthorized(t *testing.T) {
	for _, tc := range []struct {
		query               string
		status              int
		profile, projection string
	}{
		{"", 200, "", ""},
		{"?tool_argument_projection=tool-arguments%2Fv2", 200, "", agenteval.ToolArgumentProjectionV2},
		{"?evidence_read_profile=bounded-large%2Fv1", 200, agenteval.EvidenceReadProfileLargeV1, ""},
		{"?evidence_read_profile=bounded-large%2Fv1&tool_argument_projection=tool-arguments%2Fv2", 200, agenteval.EvidenceReadProfileLargeV1, agenteval.ToolArgumentProjectionV2},
		{"?evidence_read_profile=unlimited", 400, "", ""},
		{"?evidence_read_profile=", 400, "", ""},
		{"?evidence_read_profile=bounded-large%2Fv1&evidence_read_profile=bounded-large%2Fv1", 400, "", ""},
		{"?max_bytes=99999999", 400, "", ""},
	} {
		t.Run(tc.query, func(t *testing.T) {
			port := &profileInspection{}
			m := &Module{inspection: port}
			r := httptest.NewRequest(http.MethodGet, "/trajectories/root"+tc.query, nil)
			r.Header.Set("X-Authentication-Session", "current-session")
			r.Header.Set("X-Authentication-Revision", "1")
			w := httptest.NewRecorder()
			m.inspect(w, r, Actor{Browser: true, PrincipalType: "user", PrincipalID: "owner"}, []string{"trajectories", "root"})
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("invalid response", w.Code, w.Header())
			}
			if tc.status == 200 && (port.calls != 1 || port.profile != tc.profile || port.projection != tc.projection) {
				t.Fatal("read profile was not bound independently of projection", port)
			}
			if tc.status != 200 && port.calls != 0 {
				t.Fatal("invalid profile reached protected source")
			}
		})
	}
	port := &profileInspection{err: ErrForbidden}
	m := &Module{inspection: port}
	r := httptest.NewRequest(http.MethodGet, "/trajectories/root?evidence_read_profile=bounded-large%2Fv1", nil)
	r.Header.Set("X-Authentication-Session", "current-session")
	r.Header.Set("X-Authentication-Revision", "1")
	w := httptest.NewRecorder()
	m.inspect(w, r, Actor{Browser: true, PrincipalType: "user", PrincipalID: "owner"}, []string{"trajectories", "root"})
	if w.Code != 403 {
		t.Fatal("large reads bypassed source revocation")
	}
	r.Header.Del("X-Authentication-Revision")
	w = httptest.NewRecorder()
	m.inspect(w, r, Actor{Browser: true, PrincipalType: "user", PrincipalID: "owner"}, []string{"trajectories", "root"})
	if w.Code != 401 || port.calls != 1 {
		t.Fatal("unauthenticated read reached source")
	}
}
