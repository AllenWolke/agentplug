package capability

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// RuntimeToolDescriptor is installed by the operator, never selected by input.
// Published policies may tighten this minimum risk boundary, not weaken it.
type RuntimeToolDescriptor struct {
	ExecutionType  string `json:"execution_type"`
	Risk           string `json:"risk"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func (d RuntimeToolDescriptor) Validate() error {
	if d.Risk != "read_only" && d.Risk != "write" && d.Risk != "high" {
		return errors.New("invalid runtime risk")
	}
	max := 5
	switch d.ExecutionType {
	case "tool":
		if d.Risk == "read_only" {
			max = 3
		}
	case "api":
	case "code":
		if d.Risk == "read_only" || d.TimeoutSeconds < 10 {
			return errors.New("code requires an isolated, explicitly approved operation")
		}
		max = 60
	default:
		return errors.New("invalid runtime executor")
	}
	if d.TimeoutSeconds < 1 || d.TimeoutSeconds > max {
		return errors.New("invalid runtime timeout")
	}
	return nil
}

type RuntimeToolDescriber interface {
	DescribeTool(string) (RuntimeToolDescriptor, bool)
}

type RegisteredRuntimeExecutor interface {
	ToolProvider
	RuntimeToolDescriber
	RegisteredTools() []string
}

type runtimeToolPreflight interface {
	ValidateToolCommand(ToolCommand) error
}

func (d *ExecutionDispatcher) ValidateToolCommand(c ToolCommand) error {
	if d == nil {
		return errors.New("runtime unavailable")
	}
	binding, found := d.bindings[c.Name]
	if !found {
		return errors.New("runtime tool not registered")
	}
	if preflight, supported := binding.executor.(runtimeToolPreflight); supported {
		return preflight.ValidateToolCommand(c)
	}
	return nil
}

// Only the platform's isolated runner may register Code execution. A custom
// provider declaring execution_type=code is not evidence of a sandbox.
type isolatedCodeExecutor interface{ isolatedCodeRuntime() }

type runtimeDispatchBinding struct {
	descriptor RuntimeToolDescriptor
	executor   RegisteredRuntimeExecutor
}

// ExecutionDispatcher is immutable once installed. Code executors must enforce
// their sandbox boundary themselves; a descriptor alone supplies no isolation.
type ExecutionDispatcher struct {
	bindings map[string]runtimeDispatchBinding
}

func NewExecutionDispatcher(executors ...RegisteredRuntimeExecutor) (*ExecutionDispatcher, error) {
	d := &ExecutionDispatcher{bindings: map[string]runtimeDispatchBinding{}}
	for _, executor := range executors {
		var err error
		d, err = d.WithExecutor(executor)
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *ExecutionDispatcher) WithExecutor(executor RegisteredRuntimeExecutor) (*ExecutionDispatcher, error) {
	if executor == nil {
		return nil, errors.New("runtime executor required")
	}
	result := &ExecutionDispatcher{bindings: map[string]runtimeDispatchBinding{}}
	if d != nil {
		for name, binding := range d.bindings {
			result.bindings[name] = binding
		}
	}
	names := executor.RegisteredTools()
	if len(names) == 0 || len(names)+len(result.bindings) > 128 {
		return nil, errors.New("runtime registry exceeds bounds")
	}
	for _, name := range names {
		descriptor, found := executor.DescribeTool(name)
		if descriptor.ExecutionType == "code" {
			if _, isolated := executor.(isolatedCodeExecutor); !isolated {
				return nil, errors.New("isolated code runtime required")
			}
		}
		if name == "" || isNotificationTool(name) || len(name) > 128 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\x00\r\n") || !found || !executor.Supports(name) || descriptor.Validate() != nil {
			return nil, errors.New("invalid runtime registration")
		}
		if _, duplicate := result.bindings[name]; duplicate {
			return nil, errors.New("duplicate runtime registration")
		}
		result.bindings[name] = runtimeDispatchBinding{descriptor, executor}
	}
	return result, nil
}

func (d *ExecutionDispatcher) Supports(name string) bool {
	_, found := d.DescribeTool(name)
	return found
}
func (d *ExecutionDispatcher) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	if d == nil {
		return RuntimeToolDescriptor{}, false
	}
	binding, found := d.bindings[name]
	return binding.descriptor, found
}
func (d *ExecutionDispatcher) RegisteredTools() []string {
	names := []string{}
	if d != nil {
		for name := range d.bindings {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
func (d *ExecutionDispatcher) ExecutionType(name string) string {
	descriptor, _ := d.DescribeTool(name)
	return descriptor.ExecutionType
}

// Receipt delegation is read-only at the executor. The gateway owns any
// separately authorized ledger reconciliation; dispatch never replays code.
func (d *ExecutionDispatcher) LookupToolReceipt(ctx context.Context, q ToolReceiptQuery) (map[string]any, bool, error) {
	if d == nil {
		return nil, false, nil
	}
	binding, found := d.bindings[q.Name]
	if !found {
		return nil, false, nil
	}
	port, supported := binding.executor.(BusinessToolReceiptPort)
	if !supported {
		return nil, false, nil
	}
	return port.LookupToolReceipt(ctx, q)
}
func (d *ExecutionDispatcher) Invoke(ctx context.Context, command ToolCommand) (map[string]any, error) {
	if d == nil {
		return nil, ToolNoEffectError{Err: errors.New("runtime unavailable")}
	}
	binding, found := d.bindings[command.Name]
	if !found || command.Scope.ValidateTrusted() != nil || command.CallID == "" {
		return nil, ToolNoEffectError{Err: errors.New("unregistered runtime operation")}
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(binding.descriptor.TimeoutSeconds)*time.Second)
	defer cancel()
	// No goroutine timeout or host fallback: executors must honor cancellation.
	return binding.executor.Invoke(callCtx, command)
}

func (m *Module) RuntimeToolDescriptor(name string) (RuntimeToolDescriptor, bool) {
	if isNotificationTool(name) {
		return RuntimeToolDescriptor{ExecutionType: "tool", Risk: "write", TimeoutSeconds: 5}, true
	}
	if m.tools == nil || !m.tools.Supports(name) {
		return RuntimeToolDescriptor{}, false
	}
	provider, ok := m.tools.(RuntimeToolDescriber)
	if !ok {
		return RuntimeToolDescriptor{}, false
	}
	d, found := provider.DescribeTool(name)
	if d.ExecutionType == "code" {
		if _, dispatcher := m.tools.(*ExecutionDispatcher); !dispatcher {
			if _, isolated := m.tools.(isolatedCodeExecutor); !isolated {
				return RuntimeToolDescriptor{}, false
			}
		}
	}
	return d, found && d.Validate() == nil
}

func (m *Module) runtimeConfirmationRequired(policy []string, name string) bool {
	descriptor, found := m.RuntimeToolDescriptor(name)
	return !found || descriptor.Risk != "read_only" || toolRequiresConfirmation(policy, name)
}
