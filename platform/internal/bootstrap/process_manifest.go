package bootstrap

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ProcessManifest describes the process ownership boundary of the modular
// monolith.  It is deliberately data-only so a future microservice bootstrap
// can reuse the same module list and replace only the composition adapter.
//
// ProcessManifest 描述模块化单体的进程所有权边界。它保持为纯数据结构，
// 未来拆分微服务时可以复用同一份模块清单，只替换组合适配器。
type ProcessManifest struct {
	Name               string
	Binary             string
	TrustedModules     []string
	ExternalProcesses  []string
	ForbiddenInProcess []string
}

// DefaultSingleProcessManifest is the authoritative list for the platform
// process. Agent runtimes and untrusted plugins stay outside this list.
// The knowledge module owns platform source/index management; PostgreSQL
// storage remains an external dependency rather than an in-process database.
//
// DefaultSingleProcessManifest 是平台进程的权威清单。知识管理属于可信平台
// 模块，数据库仍是外部依赖；Agent Runtime 和不可信插件独立部署。
func DefaultSingleProcessManifest() ProcessManifest {
	return ProcessManifest{
		Name:   "platform-app",
		Binary: "platform",
		TrustedModules: []string{
			"agent-factory",
			"audit",
			"capability",
			"catalog",
			"conversation",
			"evaluation-product",
			"execution",
			"identity",
			"knowledge",
			"model-governance",
			"notification",
			"policyasset",
			"usage-cost",
		},
		ExternalProcesses: []string{
			"frontend",
		},
		ForbiddenInProcess: []string{
			"go-backend",
			"go-harness",
			"evaluation-worker",
			"notification-service",
			"usage-reconciler",
		},
	}
}

// Validate checks the manifest itself and rejects a process that claims an
// external/legacy component as a trusted in-process module.  This is a
// fail-closed guard against silently recreating the old double-process
// topology when a new module is registered.
//
// Validate 校验清单自身，并拒绝把外部/遗留组件声明为可信进程模块，防止
// 新增模块时悄悄恢复旧的双进程拓扑。
func (m ProcessManifest) Validate() error {
	if strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Binary) == "" {
		return errors.New("process manifest name and binary are required")
	}
	trusted, err := uniqueNames("trusted module", m.TrustedModules)
	if err != nil {
		return err
	}
	external, err := uniqueNames("external process", m.ExternalProcesses)
	if err != nil {
		return err
	}
	forbidden, err := uniqueNames("forbidden process", m.ForbiddenInProcess)
	if err != nil {
		return err
	}
	for _, name := range trusted {
		if contains(external, name) || contains(forbidden, name) {
			return fmt.Errorf("process %q is both trusted and external/forbidden", name)
		}
	}
	return nil
}

func uniqueNames(kind string, names []string) ([]string, error) {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			return nil, fmt.Errorf("%s name cannot be empty", kind)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate %s %q", kind, name)
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func contains(names []string, target string) bool {
	for _, name := range names {
		if name == target {
			return true
		}
	}
	return false
}

// ValidateRegistered ensures the production composition matches the declared
// module set exactly and no legacy process has been registered as a platform
// module. New modules must be added to the manifest in the same change.
//
// ValidateRegistered 确保生产组合包含所有可信模块，且没有把遗留进程注册为
// 平台模块。注册模块与进程清单必须精确一致，防止清单外模块绕过边界审查。
func (r *ModuleRegistry) ValidateRegistered(manifest ProcessManifest) error {
	if r == nil {
		return errors.New("module registry is required")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	r.mu.RLock()
	registered := make([]string, 0, len(r.modules))
	for name := range r.modules {
		registered = append(registered, name)
	}
	r.mu.RUnlock()
	for _, name := range registered {
		if contains(manifest.ForbiddenInProcess, name) {
			return fmt.Errorf("legacy process %q cannot be registered in platform", name)
		}
		if !contains(manifest.TrustedModules, name) {
			return fmt.Errorf("registered module %q is missing from the process manifest", name)
		}
	}
	for _, name := range manifest.TrustedModules {
		if !contains(registered, name) {
			return fmt.Errorf("required platform module %q is not registered", name)
		}
	}
	return nil
}
