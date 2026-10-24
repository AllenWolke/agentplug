package agentplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const MaximumCheckpointRevisions uint64 = 4096

func checkpointReplyLimit(result map[string]any) (uint64, error) {
	if result == nil {
		return 0, publicError("STATE_CAPACITY_INVALID")
	}
	raw, exists := result["checkpoint_history"]
	if !exists {
		return 64, nil
	}
	history, ok := raw.(map[string]any)
	if !ok || len(history) != 2 || history["version"] != "checkpoint-history/v1" {
		return 0, publicError("STATE_CAPACITY_INVALID")
	}
	limit, ok := handoffUint64(history["max_revisions"])
	if !ok || limit < 1 || limit > MaximumCheckpointRevisions {
		return 0, publicError("STATE_CAPACITY_INVALID")
	}
	return limit, nil
}

func (c *CapabilityClient) checkpointScopeKeyLocked() string {
	identity := []any{}
	for _, name := range []string{"tenant_id", "department_id", "application_id", "installation_id", "agent_instance_id", "agent_id", "agent_version_id", "principal_type", "actor_id", "session_id", "task_id", "memory_policy_id", "authorization_epoch"} {
		identity = append(identity, c.context[name])
	}
	key, _ := publicDigest(identity)
	return key
}

func (c *CapabilityClient) checkpointRevisionLimit() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit := c.checkpointLimits[c.checkpointScopeKeyLocked()]; limit != 0 {
		return limit
	}
	return 64
}

func (c *CapabilityClient) rememberCheckpointCapacity(result map[string]any) (map[string]any, error) {
	limit, err := checkpointReplyLimit(result)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.checkpointScopeKeyLocked()
	if _, exists := result["checkpoint_history"]; !exists {
		delete(c.checkpointLimits, key)
		return result, nil
	}
	if c.checkpointLimits == nil || len(c.checkpointLimits) >= 32 {
		c.checkpointLimits = map[string]uint64{}
	}
	c.checkpointLimits[key] = limit
	return result, nil
}

const CheckpointCursorSchema = "schema://agentplug/checkpoint-cursor/v1"
const checkpointCursorNamespace = "checkpoint-cursor"

type CheckpointCursor struct {
	port     CapabilityPort
	key      string
	state    map[string]any
	revision uint64
}

func OpenCheckpointCursor(ctx context.Context, port CapabilityPort, key, inputHash string, total int) (*CheckpointCursor, error) {
	if port == nil || requirePublicName(key) != nil || len(inputHash) != 64 || total < 0 || total > 1000 {
		return nil, publicError("CURSOR_CONFIG_INVALID")
	}
	if b, e := hex.DecodeString(inputHash); e != nil || len(b) != 32 {
		return nil, publicError("CURSOR_CONFIG_INVALID")
	}
	loaded, err := port.LoadCheckpoint(ctx, checkpointCursorNamespace, key, CheckpointCursorSchema, 0)
	if err != nil {
		return nil, err
	}
	limit, err := checkpointReplyLimit(loaded)
	if err != nil {
		return nil, err
	}
	if uint64(2*total+1) > limit {
		return nil, publicError("CURSOR_CAPACITY_INSUFFICIENT")
	}
	empty := sha256.Sum256(nil)
	emptyDigest := hex.EncodeToString(empty[:])
	cursor := &CheckpointCursor{port: port, key: key}
	if loaded["checkpoint"] == nil {
		phase := "ready"
		if total == 0 {
			phase = "completed"
		}
		state := map[string]any{"version": "checkpoint-cursor/v1", "input_hash": inputHash, "total": total, "index": 0, "phase": phase, "result_digest": emptyDigest}
		if err := AuthorizeRuntimeRecoveryStart(ctx, checkpointCursorNamespace, key, CheckpointCursorSchema, inputHash); err != nil {
			return nil, err
		}
		if err := cursor.save(ctx, state); err != nil {
			return nil, err
		}
		return cursor, nil
	}
	cp, ok := loaded["checkpoint"].(map[string]any)
	if !ok {
		return nil, publicError("CURSOR_STATE_REJECTED")
	}
	state, ok := cp["value"].(map[string]any)
	if !ok {
		return nil, publicError("CURSOR_STATE_REJECTED")
	}
	revision, rv := handoffUint64(cp["revision"])
	count, tc := handoffUint64(state["total"])
	index, ix := handoffUint64(state["index"])
	phase, _ := state["phase"].(string)
	digest, _ := state["result_digest"].(string)
	hashBytes, hashErr := hex.DecodeString(digest)
	expected := 2*index + 1
	if phase == "pending" {
		expected++
	}
	if !rv || !tc || !ix || revision < 1 || revision > limit || len(state) != 6 || state["version"] != "checkpoint-cursor/v1" || state["input_hash"] != inputHash || count != uint64(total) || index > count ||
		(phase != "ready" && phase != "pending" && phase != "completed") || (phase == "completed") != (index == count) || hashErr != nil || len(hashBytes) != 32 || index == 0 && digest != emptyDigest || revision != expected {
		return nil, publicError("CURSOR_STATE_REJECTED")
	}
	cursor.state, err = publicClone(state)
	cursor.revision = revision
	return cursor, err
}

func (c *CheckpointCursor) Index() int      { v, _ := handoffUint64(c.state["index"]); return int(v) }
func (c *CheckpointCursor) Completed() bool { return c.state["phase"] == "completed" }
func (c *CheckpointCursor) Begin(ctx context.Context) (bool, error) {
	if c.Completed() {
		return false, publicError("CURSOR_ALREADY_COMPLETED")
	}
	if c.state["phase"] == "pending" {
		if client, ok := c.port.(interface{ ValidateCurrentExecution(context.Context) error }); ok {
			if err := client.ValidateCurrentExecution(ctx); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	state, err := publicClone(c.state)
	if err != nil {
		return false, err
	}
	state["phase"] = "pending"
	return false, c.save(ctx, state)
}
func (c *CheckpointCursor) Confirm(ctx context.Context, resultHash string) error {
	b, err := hex.DecodeString(resultHash)
	if c.state["phase"] != "pending" || err != nil || len(b) != 32 {
		return publicError("CURSOR_CONFIRMATION_REJECTED")
	}
	index := c.Index()
	chain := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", c.state["result_digest"], index, resultHash)))
	state, err := publicClone(c.state)
	if err != nil {
		return err
	}
	state["index"] = index + 1
	state["result_digest"] = hex.EncodeToString(chain[:])
	state["phase"] = "ready"
	count, _ := handoffUint64(state["total"])
	if index+1 == int(count) {
		state["phase"] = "completed"
	}
	return c.save(ctx, state)
}
func (c *CheckpointCursor) save(ctx context.Context, state map[string]any) error {
	result, err := c.port.SaveCheckpoint(ctx, checkpointCursorNamespace, c.key, CheckpointCursorSchema, fmt.Sprintf("cursor-%d", c.revision+1), c.revision, state)
	if err != nil {
		return err
	}
	cp, ok := result["checkpoint"].(map[string]any)
	if !ok {
		return publicError("CURSOR_STATE_REJECTED")
	}
	revision, ok := handoffUint64(cp["revision"])
	a, e1 := publicDigest(cp["value"])
	b, e2 := publicDigest(state)
	if !ok || revision != c.revision+1 || e1 != nil || e2 != nil || a != b {
		return publicError("CURSOR_STATE_REJECTED")
	}
	c.state, err = publicClone(state)
	if err != nil {
		return err
	}
	c.revision = revision
	return nil
}

func (c *CapabilityClient) postCheckpoint(ctx context.Context, input map[string]any) (map[string]any, error) {
	result, err := c.Post(ctx, "/internal/state/checkpoint", input)
	if err != nil {
		return nil, err
	}
	return c.rememberCheckpointCapacity(result)
}
