package execution

import (
	"context"
	"encoding/json"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ReadRunProvenance returns only evidence metadata after matching the durable
// task owner to the Run. It never exposes request bodies or model responses.
// ReadRunProvenance 核对持久化任务所有者与 Run，仅返回来源，绝不泄露请求或模型正文。
func (m *Module) ReadRunProvenance(ctx context.Context, scope sharedkernel.Scope) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil || scope.RunID == "" || scope.PrincipalType == "" || scope.AgentID == "" || scope.AgentInstanceID == "" || scope.SessionID == "" {
		return nil, sharedkernel.ErrInvalidScope
	}
	run, err := m.store.Get(scope.RunID)
	if errors.Is(err, platformruntime.ErrRunNotFound) {
		// An independently created task may not have a Run yet. It is unknown,
		// not synthetic/real evidence; do not invent an outcome or rerun work.
		// 独立创建的任务可能尚未执行，只能标未知，不能造结果或重跑。
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	actual := run.Scope
	if actual.TenantID != scope.TenantID || actual.DepartmentID != scope.DepartmentID || actual.ApplicationID != scope.ApplicationID || actual.PrincipalType != scope.PrincipalType || actual.PrincipalID != scope.PrincipalID || actual.AgentID != scope.AgentID || actual.AgentInstanceID != scope.AgentInstanceID || actual.SessionID != scope.SessionID {
		return nil, sharedkernel.ErrInvalidScope
	}
	outcome, err := m.store.GetOutcome(run.ID)
	if errors.Is(err, platformruntime.ErrRunNotFound) {
		return nil, nil // Not produced yet, not proof of real data / 尚无结果，不代表真实数据。
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var output struct {
		Provenance *struct {
			Synthetic  bool   `json:"synthetic"`
			SourceType string `json:"source_type"`
			DataSource string `json:"data_source"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(outcome.OutputJSON, &output); err != nil {
		return nil, errors.New("invalid persisted run provenance")
	}
	if output.Provenance == nil {
		return nil, nil
	}
	return map[string]any{"synthetic": output.Provenance.Synthetic, "source_type": output.Provenance.SourceType, "data_source": output.Provenance.DataSource}, nil
}
