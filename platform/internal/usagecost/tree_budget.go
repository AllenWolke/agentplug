package usagecost

// RunTreeBudgetCounters is a root Run's aggregate accounting state. Cost is
// measured in integer micros; tokens count input AND output across all model
// calls in the root and its descendants. Admission checks used plus held.
// These arithmetic functions do not establish lineage or permission. The
// durable store must lock the verified root, bind an immutable request receipt,
// and commit the counters with its reservation in the same transaction.
type RunTreeBudgetCounters struct {
	LimitMicros int64 `json:"limit_micros"`
	LimitTokens int64 `json:"limit_tokens"`
	UsedMicros  int64 `json:"used_micros"`
	UsedTokens  int64 `json:"used_tokens"`
	HeldMicros  int64 `json:"held_micros"`
	HeldTokens  int64 `json:"held_tokens"`
}

type RunTreeBudgetHold struct {
	Micros int64 `json:"micros"`
	Tokens int64 `json:"tokens"`
}

func (s RunTreeBudgetCounters) Exhausted() bool {
	return s.Validate() != nil || s.UsedTokens+s.HeldTokens >= s.LimitTokens || s.UsedMicros+s.HeldMicros > s.LimitMicros || s.LimitMicros > 0 && s.UsedMicros+s.HeldMicros >= s.LimitMicros
}

func (s RunTreeBudgetCounters) Validate() error {
	if s.LimitMicros < 0 || s.LimitTokens < 0 || s.UsedMicros < 0 || s.UsedTokens < 0 || s.HeldMicros < 0 || s.HeldTokens < 0 ||
		s.HeldMicros > maxInt64-s.UsedMicros || s.HeldTokens > maxInt64-s.UsedTokens {
		return ErrInvalidUsage
	}
	return nil
}

func (h RunTreeBudgetHold) Validate() error {
	if h.Micros < 0 || h.Tokens < 0 {
		return ErrInvalidUsage
	}
	return nil
}

// ReserveRunTreeBudget checks BOTH limits. Zero is a zero allowance, not
// unlimited. No expired or uncertain hold is automatically reclaimed here.
func ReserveRunTreeBudget(current RunTreeBudgetCounters, hold RunTreeBudgetHold) (RunTreeBudgetCounters, error) {
	if current.Validate() != nil || hold.Validate() != nil {
		return current, ErrInvalidUsage
	}
	cost := current.UsedMicros + current.HeldMicros
	tokens := current.UsedTokens + current.HeldTokens
	if cost > current.LimitMicros || tokens > current.LimitTokens || hold.Micros > current.LimitMicros-cost || hold.Tokens > current.LimitTokens-tokens {
		return current, ErrBudgetExceeded
	}
	current.HeldMicros += hold.Micros
	current.HeldTokens += hold.Tokens
	return current, nil
}

// SettleRunTreeBudget replaces a known request's hold with ACTUAL usage. A
// provider's known billable result must be recorded even when it exceeds the
// estimate or limit. exceeded stops future admission; it does not discard the
// charge. Only a durable matching reservation may supply the hold, and an
// idempotent settled receipt must return its saved result without applying twice.
func SettleRunTreeBudget(current RunTreeBudgetCounters, hold RunTreeBudgetHold, actualMicros, inputTokens, outputTokens int64) (next RunTreeBudgetCounters, exceeded bool, err error) {
	if current.Validate() != nil || hold.Validate() != nil || actualMicros < 0 || inputTokens < 0 || outputTokens < 0 ||
		hold.Micros > current.HeldMicros || hold.Tokens > current.HeldTokens || outputTokens > maxInt64-inputTokens {
		return current, false, ErrInvalidUsage
	}
	actualTokens := inputTokens + outputTokens
	if actualMicros > maxInt64-current.UsedMicros || actualTokens > maxInt64-current.UsedTokens {
		return current, false, ErrInvalidUsage
	}
	next = current
	next.HeldMicros -= hold.Micros
	next.HeldTokens -= hold.Tokens
	next.UsedMicros += actualMicros
	next.UsedTokens += actualTokens
	if next.Validate() != nil {
		return current, false, ErrInvalidUsage
	}
	exceeded = next.UsedMicros+next.HeldMicros > next.LimitMicros || next.UsedTokens+next.HeldTokens > next.LimitTokens
	return next, exceeded, nil
}

// ReleaseRunTreeBudget is accounting for a PROVEN unbilled request. The store
// must reject unknown/running/reconciliation receipts, expiry-only evidence and
// cancellation without terminal provider evidence. This arithmetic helper
// alone is not permission to release a reservation.
func ReleaseRunTreeBudget(current RunTreeBudgetCounters, hold RunTreeBudgetHold) (RunTreeBudgetCounters, error) {
	if current.Validate() != nil || hold.Validate() != nil || hold.Micros > current.HeldMicros || hold.Tokens > current.HeldTokens {
		return current, ErrInvalidUsage
	}
	current.HeldMicros -= hold.Micros
	current.HeldTokens -= hold.Tokens
	return current, nil
}
