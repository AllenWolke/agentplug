package capability

import (
	"errors"
	"reflect"

	"github.com/lexagent/platform/internal/compensation"
)

// Operator-installed executors can supply their immutable, versioned inverse
// owner. This has no HTTP registration path and does not bypass normal IAM.
type RuntimeCancellationBinding struct {
	Registration compensation.Registration
	Tools        []string
	Step         func(ToolReceiptQuery) (compensation.Step, error)
}

type runtimeCancellationOwner interface {
	CancellationBinding(compensation.EffectRegistry, *SQLToolInvocationStore) (RuntimeCancellationBinding, error)
}

func (m *Module) RuntimeCancellationBindings(ledger compensation.EffectRegistry, tools *SQLToolInvocationStore) ([]RuntimeCancellationBinding, error) {
	if m == nil || ledger == nil || tools == nil {
		return nil, compensation.ErrUnavailable
	}
	registry, ok := m.tools.(*ExecutionDispatcher)
	if !ok {
		return nil, compensation.ErrUnavailable
	}
	result := []RuntimeCancellationBinding{}
	seen := map[string]bool{}
	for _, name := range registry.RegisteredTools() {
		binding := registry.bindings[name]
		owner, has := binding.executor.(runtimeCancellationOwner)
		if !has {
			continue
		}
		// Owner identity must be a pointer. Never compare arbitrary interface
		// values: an installed executor may contain a slice/map.
		ownerValue := reflect.ValueOf(binding.executor)
		if ownerValue.Kind() != reflect.Pointer || ownerValue.IsNil() {
			return nil, compensation.ErrInvalid
		}
		inverse, err := owner.CancellationBinding(ledger, tools)
		if err != nil {
			return nil, err
		}
		key := inverse.Registration.Provider + "\x00" + inverse.Registration.Version
		if seen[key] {
			continue
		}
		if inverse.Step == nil || inverse.Registration.Port == nil || len(inverse.Tools) == 0 {
			return nil, compensation.ErrInvalid
		}
		for _, tool := range inverse.Tools {
			actual, registered := registry.bindings[tool]
			actualValue := reflect.ValueOf(actual.executor)
			if !registered || !actualValue.IsValid() || actualValue.Kind() != reflect.Pointer || actualValue.Type() != ownerValue.Type() || actualValue.Pointer() != ownerValue.Pointer() || actual.descriptor.Risk == "read_only" {
				return nil, errors.New("runtime inverse ownership conflict")
			}
		}
		seen[key] = true
		result = append(result, inverse)
	}
	return result, nil
}
