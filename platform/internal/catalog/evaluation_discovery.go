package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	agenteval "github.com/lexagent/agent-evaluation"
)

// DiscoverEvaluationAgents exposes no endpoint or manifest. All visibility and
// invocation hints come from current Identity, checked again after probing.
func (m *Module) DiscoverEvaluationAgents(ctx context.Context, actor ControlActor, canEvaluate bool) ([]agenteval.Agent, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	reader, ok := m.store.(AvailableAgentReader)
	projector, has := m.agentAccess.(AgentActionProjector)
	if !ok || !has || m.controlAuth == nil || actor.PrincipalType != "user" {
		return nil, ErrCatalogForbidden
	}
	scope := ControlScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	if err := m.controlAuth.AuthorizeCatalogControl(ctx, actor, ControlRequestable, scope); err != nil {
		return nil, err
	}
	available, err := reader.ListAvailableAgents(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, v := range available {
		ids = append(ids, v.InstallationID)
	}
	permissions, err := projector.ProjectAgentActions(ctx, actor, ids)
	if err != nil {
		return nil, err
	}
	items := []agenteval.Agent{}
	type healthTask struct {
		index      int
		deployment Deployment
		path       string
	}
	tasks := []healthTask{}
	for _, v := range available {
		if !permissions[v.InstallationID]["discover"] {
			continue
		}
		a := agenteval.Agent{AgentID: v.AgentID, Name: v.Name, InstallationID: v.InstallationID, VersionID: v.VersionID, SemanticVersion: v.SemanticVersion, Health: "unknown", Language: "unknown", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		installation, e := m.store.GetInstallation(ctx, v.InstallationID)
		if e != nil || installation.Status != InstallationActive || installation.VersionID != v.VersionID {
			a.Reason = "INSTALLATION_CHANGED"
			items = append(items, a)
			continue
		}
		a.Revision = installation.Revision
		version, e := m.store.GetVersion(ctx, v.VersionID)
		if e != nil || version.Status != DefinitionPublished || version.Validate() != nil {
			a.Reason = "VERSION_UNAVAILABLE"
			items = append(items, a)
			continue
		}
		var manifest agentManifest
		if json.Unmarshal(version.Manifest, &manifest) != nil {
			a.Reason = "MANIFEST_INVALID"
			items = append(items, a)
			continue
		}
		// Current manifests may specify runtime language; absence stays unknown.
		var metadata struct {
			Runtime struct {
				Language string `json:"language"`
			} `json:"runtime"`
			Metadata struct {
				SDK string `json:"sdk"`
			} `json:"metadata"`
		}
		if json.Unmarshal(version.Manifest, &metadata) == nil {
			language := metadata.Runtime.Language
			if language == "" {
				language = strings.TrimPrefix(metadata.Metadata.SDK, "sdk/")
			}
			switch language {
			case "go", "golang":
				a.Language = "go"
			case "python", "java":
				a.Language = language
			}
		}
		deployments, e := m.store.ListDeployments(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID, v.InstallationID, 1)
		if e != nil || len(deployments) != 1 {
			a.Reason = "DEPLOYMENT_UNAVAILABLE"
			items = append(items, a)
			continue
		}
		d := deployments[0]
		if d.AgentVersionID != v.VersionID || d.Status != DeploymentReady || d.DesiredRevision == 0 || d.ObservedRevision != d.DesiredRevision || d.ManifestHash != version.ManifestHash || d.ArtifactDigest != version.ArtifactDigest {
			a.Health = "offline"
			a.Reason = "LATEST_DEPLOYMENT_NOT_READY"
			items = append(items, a)
			continue
		}
		tasks = append(tasks, healthTask{index: len(items), deployment: d, path: manifest.Runtime.HealthPath})
		items = append(items, a)
	}
	// Keep slow/offline deployments from monopolizing request goroutines.
	sem := make(chan struct{}, 8)
	var probes sync.WaitGroup
	defer probes.Wait()
	for _, task := range tasks {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		probes.Add(1)
		go func(task healthTask) {
			defer probes.Done()
			defer func() { <-sem }()
			item := &items[task.index]
			item.Health, item.Reason = probeEvaluationHealth(ctx, task.deployment, task.path)
			item.CheckedAt = time.Now().UTC().Format(time.RFC3339)
			item.CanEvaluate = item.Health == "online" && canEvaluate && permissions[item.InstallationID]["run"]
		}(task)
	}
	probes.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Fail closed on revocation while the health network read was in flight.
	permissions, err = projector.ProjectAgentActions(ctx, actor, ids)
	if err != nil {
		return nil, err
	}
	filtered := items[:0]
	for _, a := range items {
		if permissions[a.InstallationID]["discover"] {
			current, e := m.store.GetInstallation(ctx, a.InstallationID)
			if e != nil {
				return nil, e
			}
			if current.VersionID != a.VersionID || current.Revision != a.Revision || current.Status != InstallationActive {
				a.Health = "unknown"
				a.Reason = "INSTALLATION_CHANGED"
				a.CanEvaluate = false
			}
			a.CanEvaluate = a.CanEvaluate && permissions[a.InstallationID]["run"]
			filtered = append(filtered, a)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].InstallationID < filtered[j].InstallationID })
	return filtered, nil
}

func probeEvaluationHealth(ctx context.Context, d Deployment, path string) (string, string) {
	if d.Transport != "http" {
		return "unknown", "HEALTH_TRANSPORT_UNSUPPORTED"
	}
	if !validDeploymentEndpoint(d.EndpointRef, d.Transport) || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\\r\n") {
		return "unknown", "HEALTH_TARGET_INVALID"
	}
	u, err := url.Parse(d.EndpointRef)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "unknown", "HEALTH_TARGET_INVALID"
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "unknown", "HEALTH_TARGET_INVALID"
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return "offline", "HEALTH_CHECK_FAILED"
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return "online", ""
	}
	return "offline", "HEALTH_CHECK_REJECTED"
}

// EvaluationFixtureDeclaration reads only the immutable registration marker;
// the admission port additionally pins scope, deployment, policy and provider.
func (m *Module) EvaluationFixtureDeclaration(ctx context.Context, id string) (bool, error) {
	version, e := m.store.GetVersion(ctx, id)
	if e != nil {
		return false, e
	}
	if version.Status != DefinitionPublished || version.Validate() != nil {
		return false, ErrEvaluationTargetUnavailable
	}
	var declaration struct {
		Metadata struct {
			EvaluationOnly bool   `json:"evaluation_only"`
			Fixture        string `json:"evaluation_fixture"`
		} `json:"metadata"`
	}
	if e = json.Unmarshal(version.Manifest, &declaration); e != nil {
		return false, e
	}
	return declaration.Metadata.EvaluationOnly && declaration.Metadata.Fixture == "agent-eval-fixture/v1", nil
}
