package agenteval

import "encoding/json"

// EvidenceReadProfileLargeV1 changes bounded read capacity, never source IAM,
// redaction, individual argument size, execution budgets or metric eligibility.
const EvidenceReadProfileLargeV1 = "bounded-large/v1"

type TrajectoryReadLimits struct {
	Events         int
	EventBytes     int
	ToolInputs     int
	ToolInputBytes int
}

func TrajectoryReadLimitsFor(profile string) (TrajectoryReadLimits, bool) {
	switch profile {
	case "":
		return TrajectoryReadLimits{Events: 10000, ToolInputs: 10000, ToolInputBytes: 2 << 20}, true
	case EvidenceReadProfileLargeV1:
		// A 1000-item Run retains two independently confirmed writes per item;
		// its full evidence can exceed 32 MiB. Capacity remains explicit and
		// bounded, with the same exact-Run authorization and per-item redaction.
		return TrajectoryReadLimits{Events: 50000, EventBytes: 64 << 20, ToolInputs: 20000, ToolInputBytes: 64 << 20}, true
	default:
		return TrajectoryReadLimits{}, false
	}
}

// TrajectoryEventBytes includes JSON escaping and array separators. Source
// readers use it before retaining a descendant; aggregation enforces the same
// limit independently. It excludes outputs, which retain their own old bound.
func TrajectoryEventBytes(events []Event) (int, error) {
	n := 2
	for i, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return 0, err
		}
		n += len(encoded)
		if i > 0 {
			n++
		}
	}
	return n, nil
}
