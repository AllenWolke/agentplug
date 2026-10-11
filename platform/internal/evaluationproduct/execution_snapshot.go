package evaluationproduct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrSnapshotInvalid indicates that persisted evaluation inputs are malformed,
// unsupported, or internally inconsistent. It is deliberately distinct from
// ErrNotFound so callers can fail a run without revealing cross-scope records.
// ErrSnapshotInvalid 表示已持久化的评测输入损坏、不受支持或内部不一致。
var ErrSnapshotInvalid = errors.New("evaluation execution snapshot invalid")

// ExecutionRequest is an immutable-by-contract view of the exact published
// suite, dataset, and metric revisions selected for one persisted Run. Its
// fields are private and slice-bearing accessors return defensive copies.
// ExecutionRequest 是单个 Run 固定使用的发布版 Suite、Dataset、Metric 快照；字段私有且切片访问器返回副本。
type ExecutionRequest struct {
	runID                string
	idempotencyKey       string
	leaseToken           string
	scope                Scope
	suite                SuiteSnapshot
	dataset              DatasetSnapshot
	metrics              []MetricSnapshot
	agentID              string
	agentVersionID       string
	installationID       string
	installationRevision uint64
}

type SuiteSnapshot struct {
	ID           string
	Revision     uint64
	SnapshotHash string
	Name         string
	Version      string
	DatasetID    string
	AgentID      string
	AgentVersion string
	MetricIDs    []string
}

type DatasetSnapshot struct {
	ID          string
	Revision    uint64
	Name        string
	Version     string
	SourceType  string
	ContentHash string
	Cases       []json.RawMessage
}

type MetricSnapshot struct {
	ID            string
	Revision      uint64
	MetricID      string
	Version       string
	Name          string
	Kind          string
	PluginID      string
	PluginVersion string
	PluginDigest  string
	Formula       json.RawMessage
	FormulaHash   string
}

func (r ExecutionRequest) RunID() string                { return r.runID }
func (r ExecutionRequest) IdempotencyKey() string       { return r.idempotencyKey }
func (r ExecutionRequest) Scope() Scope                 { return r.scope }
func (r ExecutionRequest) AgentID() string              { return r.agentID }
func (r ExecutionRequest) AgentVersionID() string       { return r.agentVersionID }
func (r ExecutionRequest) InstallationID() string       { return r.installationID }
func (r ExecutionRequest) InstallationRevision() uint64 { return r.installationRevision }

func (r ExecutionRequest) Suite() SuiteSnapshot {
	suite := r.suite
	suite.MetricIDs = append([]string(nil), r.suite.MetricIDs...)
	return suite
}

func (r ExecutionRequest) Dataset() DatasetSnapshot {
	dataset := r.dataset
	dataset.Cases = cloneRawMessages(r.dataset.Cases)
	return dataset
}

func (r ExecutionRequest) Metrics() []MetricSnapshot {
	metrics := make([]MetricSnapshot, len(r.metrics))
	for i, metric := range r.metrics {
		metrics[i] = metric
		metrics[i].Formula = append(json.RawMessage(nil), metric.Formula...)
	}
	return metrics
}

type suiteSnapshotDocument struct {
	InstallationID       string                  `json:"installation_id,omitempty"`
	InstallationRevision uint64                  `json:"installation_revision,omitempty"`
	DatasetID            string                  `json:"dataset_id"`
	DatasetRevision      uint64                  `json:"dataset_revision"`
	DatasetHash          string                  `json:"dataset_hash"`
	AgentID              string                  `json:"agent_id"`
	AgentVersionID       string                  `json:"agent_version_id"`
	Metrics              []metricSnapshotPointer `json:"metrics"`
	snapshotHash         string                  `json:"-"`
}

type metricSnapshotPointer struct {
	ID            string `json:"id"`
	Revision      uint64 `json:"revision"`
	FormulaHash   string `json:"formula_hash"`
	PluginID      string `json:"plugin_id,omitempty"`
	PluginVersion string `json:"plugin_version,omitempty"`
	PluginDigest  string `json:"plugin_digest,omitempty"`
}

// ResolveExecutionSnapshot rehydrates the immutable inputs for a persisted
// product Run using only its trusted application scope. Store.Get is always
// scoped; a row returned with a different scope is treated as not found.
// ResolveExecutionSnapshot 使用可信应用作用域重建 Run 的不可变输入；跨作用域记录统一按不存在处理。
func ResolveExecutionSnapshot(ctx context.Context, store Store, scope Scope, run Resource) (ExecutionRequest, error) {
	return resolveExecutionSnapshot(ctx, store, scope, run, false)
}

// ResolveHistoricalExecutionSnapshot verifies the same immutable suite,
// dataset, case and metric references as ResolveExecutionSnapshot, while
// allowing a terminal product Run to serve as accounting provenance. It does
// not authorize new invocation or continuation; callers must use the live
// resolver for those decisions.
func ResolveHistoricalExecutionSnapshot(ctx context.Context, store Store, scope Scope, run Resource) (ExecutionRequest, error) {
	return resolveExecutionSnapshot(ctx, store, scope, run, true)
}

func executionSnapshotRunStateAllowed(status string, data RunData, historical bool, now time.Time) bool {
	if historical {
		switch status {
		case "running", "succeeded", "failed", "cancelling", "cancelled":
			return data.ExecutionState == status
		default:
			return false
		}
	}
	switch status {
	case "queued":
		return data.ExecutionState == "dispatch_pending" || data.ExecutionState == "queued"
	case "running":
		return data.ExecutionState == "running" && validID(data.LeaseOwner) && validID(data.LeaseToken) && data.LeaseUntil.After(now)
	default:
		return false
	}
}

func resolveExecutionSnapshot(ctx context.Context, store Store, scope Scope, run Resource, historical bool) (ExecutionRequest, error) {
	if store == nil || !scope.valid() || run.Kind != KindRun || run.Scope != scope || !validID(run.ID) || run.Revision == 0 {
		return ExecutionRequest{}, snapshotInvalid("invalid run identity or state")
	}
	var runData RunData
	if err := decodeSnapshotJSON(run.Data, &runData); err != nil {
		return ExecutionRequest{}, snapshotInvalid("invalid run data: %v", err)
	}
	if !validID(runData.SuiteID) || !validID(runData.IdempotencyKey) || !executionSnapshotRunStateAllowed(run.Status, runData, historical, time.Now()) {
		return ExecutionRequest{}, snapshotInvalid("run is not dispatchable")
	}

	suiteRow, err := getScopedResource(ctx, store, scope, KindSuite, runData.SuiteID)
	if err != nil {
		return ExecutionRequest{}, err
	}
	if suiteRow.Status != "published" || suiteRow.Revision == 0 {
		return ExecutionRequest{}, snapshotInvalid("suite is not published")
	}
	var suiteData SuiteData
	if err := decodeSnapshotJSON(suiteRow.Data, &suiteData); err != nil {
		return ExecutionRequest{}, snapshotInvalid("invalid suite data: %v", err)
	}
	if err := validateSuiteSnapshot(suiteData); err != nil {
		return ExecutionRequest{}, err
	}
	if runData.AgentID != suiteData.AgentID || runData.AgentVersionID != suiteData.AgentVersionID || runData.InstallationID != suiteData.InstallationID || runData.InstallationRevision != suiteData.InstallationRevision {
		return ExecutionRequest{}, snapshotInvalid("run agent binding differs from suite")
	}

	snapshot, err := decodeSuiteSnapshot(suiteData.Snapshot)
	if err != nil {
		return ExecutionRequest{}, err
	}
	if snapshot.snapshotHash != suiteData.SnapshotHash || snapshot.DatasetID != suiteData.DatasetID || snapshot.AgentID != suiteData.AgentID || snapshot.AgentVersionID != suiteData.AgentVersionID || snapshot.InstallationID != suiteData.InstallationID || snapshot.InstallationRevision != suiteData.InstallationRevision || !sameOrderedStrings(suiteData.MetricIDs, snapshot.metricIDs()) {
		return ExecutionRequest{}, snapshotInvalid("suite data differs from its snapshot")
	}

	datasetRow, err := getScopedResource(ctx, store, scope, KindDataset, snapshot.DatasetID)
	if err != nil {
		return ExecutionRequest{}, err
	}
	if datasetRow.Revision != snapshot.DatasetRevision {
		return ExecutionRequest{}, fmt.Errorf("dataset revision differs from suite snapshot: %w", ErrConflict)
	}
	dataset, err := verifyDataset(datasetRow, snapshot)
	if err != nil {
		return ExecutionRequest{}, err
	}

	metrics := make([]MetricSnapshot, 0, len(snapshot.Metrics))
	for _, reference := range snapshot.Metrics {
		metricRow, getErr := getScopedResource(ctx, store, scope, KindMetric, reference.ID)
		if getErr != nil {
			return ExecutionRequest{}, getErr
		}
		if metricRow.Revision != reference.Revision {
			return ExecutionRequest{}, fmt.Errorf("metric %q revision differs from suite snapshot: %w", reference.ID, ErrConflict)
		}
		metric, verifyErr := verifyMetric(metricRow, reference)
		if verifyErr != nil {
			return ExecutionRequest{}, verifyErr
		}
		metrics = append(metrics, metric)
	}

	return ExecutionRequest{
		runID:          run.ID,
		idempotencyKey: runData.IdempotencyKey,
		leaseToken:     runData.LeaseToken,
		scope:          scope,
		suite: SuiteSnapshot{
			ID: suiteRow.ID, Revision: suiteRow.Revision, SnapshotHash: suiteData.SnapshotHash,
			Name: suiteData.Name, Version: suiteData.Version, DatasetID: suiteData.DatasetID,
			AgentID: suiteData.AgentID, AgentVersion: suiteData.AgentVersionID,
			MetricIDs: append([]string(nil), suiteData.MetricIDs...),
		},
		dataset:              dataset,
		metrics:              metrics,
		agentID:              suiteData.AgentID,
		agentVersionID:       suiteData.AgentVersionID,
		installationID:       suiteData.InstallationID,
		installationRevision: suiteData.InstallationRevision,
	}, nil
}

func getScopedResource(ctx context.Context, store Store, scope Scope, kind Kind, id string) (Resource, error) {
	row, err := store.Get(ctx, scope, kind, id)
	if err != nil {
		return Resource{}, err
	}
	if row.Scope != scope || row.Kind != kind || row.ID != id {
		return Resource{}, ErrNotFound
	}
	if err := validateResource(row); err != nil {
		return Resource{}, snapshotInvalid("invalid %s resource envelope", kind)
	}
	return row, nil
}

func validateSuiteSnapshot(data SuiteData) error {
	if (data.InstallationID == "") != (data.InstallationRevision == 0) || (data.InstallationID != "" && !validID(data.InstallationID)) {
		return snapshotInvalid("invalid installation binding")
	}
	if strings.TrimSpace(data.Name) == "" || len(data.Name) > 128 || strings.TrimSpace(data.Version) == "" || len(data.Version) > 32 ||
		!validID(data.DatasetID) || !validID(data.AgentID) || !validID(data.AgentVersionID) || len(data.MetricIDs) == 0 || len(data.MetricIDs) > 100 ||
		len(data.Snapshot) == 0 || len(data.Snapshot) > 16<<10 || !validSHA256(data.SnapshotHash) {
		return snapshotInvalid("invalid suite fields")
	}
	seen := make(map[string]struct{}, len(data.MetricIDs))
	for _, id := range data.MetricIDs {
		if !validID(id) {
			return snapshotInvalid("invalid suite metric reference")
		}
		if _, exists := seen[id]; exists {
			return snapshotInvalid("duplicate suite metric reference")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func decodeSuiteSnapshot(raw json.RawMessage) (suiteSnapshotDocument, error) {
	var snapshot suiteSnapshotDocument
	if err := decodeSnapshotJSON(raw, &snapshot); err != nil {
		return suiteSnapshotDocument{}, snapshotInvalid("invalid suite snapshot: %v", err)
	}
	if (snapshot.InstallationID == "") != (snapshot.InstallationRevision == 0) || (snapshot.InstallationID != "" && !validID(snapshot.InstallationID)) {
		return suiteSnapshotDocument{}, snapshotInvalid("invalid installation snapshot")
	}
	if !validID(snapshot.DatasetID) || snapshot.DatasetRevision == 0 || !validSHA256(snapshot.DatasetHash) ||
		!validID(snapshot.AgentID) || !validID(snapshot.AgentVersionID) || len(snapshot.Metrics) == 0 || len(snapshot.Metrics) > 100 {
		return suiteSnapshotDocument{}, snapshotInvalid("incomplete suite snapshot")
	}
	seen := make(map[string]struct{}, len(snapshot.Metrics))
	for _, metric := range snapshot.Metrics {
		if !validID(metric.ID) || metric.Revision == 0 || !validSHA256(metric.FormulaHash) ||
			(metric.PluginID == "") != (metric.PluginVersion == "") || (metric.PluginID == "") != (metric.PluginDigest == "") ||
			(metric.PluginID != "" && (!validID(metric.PluginID) || strings.TrimSpace(metric.PluginVersion) == "" || !validSHA256(metric.PluginDigest))) {
			return suiteSnapshotDocument{}, snapshotInvalid("invalid metric snapshot reference")
		}
		if _, exists := seen[metric.ID]; exists {
			return suiteSnapshotDocument{}, snapshotInvalid("duplicate metric snapshot reference")
		}
		seen[metric.ID] = struct{}{}
	}
	var generic map[string]any
	if err := decodeJSONUseNumber(raw, &generic); err != nil {
		return suiteSnapshotDocument{}, snapshotInvalid("invalid suite snapshot hash input: %v", err)
	}
	encodedHash, err := contentHash(generic)
	if err != nil {
		return suiteSnapshotDocument{}, snapshotInvalid("cannot hash suite snapshot")
	}
	// SnapshotHash is checked by caller against SuiteData to keep the decoded
	// snapshot independent from its enclosing resource.
	snapshot.snapshotHash = encodedHash
	return snapshot, nil
}

func (s suiteSnapshotDocument) metricIDs() []string {
	ids := make([]string, len(s.Metrics))
	for i := range s.Metrics {
		ids[i] = s.Metrics[i].ID
	}
	return ids
}

func verifyDataset(row Resource, reference suiteSnapshotDocument) (DatasetSnapshot, error) {
	if row.Status != "published" {
		return DatasetSnapshot{}, snapshotInvalid("dataset is not published")
	}
	var data DatasetData
	if err := decodeSnapshotJSON(row.Data, &data); err != nil {
		return DatasetSnapshot{}, snapshotInvalid("invalid dataset data: %v", err)
	}
	if data.ReviewStatus != "approved" || data.ReviewerID == "" || row.CreatedBy == "" || data.ReviewerID == row.CreatedBy || data.ReviewedAt == nil || data.SampleCount != len(data.Cases) {
		return DatasetSnapshot{}, snapshotInvalid("dataset is not reviewed or sample count mismatches")
	}
	if err := validateDataset(data); err != nil {
		return DatasetSnapshot{}, snapshotInvalid("dataset content is invalid: %v", err)
	}
	actualHash, err := contentHash(data.Cases)
	if err != nil || !validSHA256(data.ContentHash) || actualHash != data.ContentHash || data.ContentHash != reference.DatasetHash {
		return DatasetSnapshot{}, snapshotInvalid("dataset content hash mismatch")
	}
	return DatasetSnapshot{ID: row.ID, Revision: row.Revision, Name: data.Name, Version: data.Version, SourceType: data.SourceType, ContentHash: data.ContentHash, Cases: cloneRawMessages(data.Cases)}, nil
}

func verifyMetric(row Resource, reference metricSnapshotPointer) (MetricSnapshot, error) {
	if row.Status != "published" {
		return MetricSnapshot{}, snapshotInvalid("metric %q is not published", row.ID)
	}
	var data MetricData
	if err := decodeSnapshotJSON(row.Data, &data); err != nil {
		return MetricSnapshot{}, snapshotInvalid("invalid metric %q data: %v", row.ID, err)
	}
	if data.Status != "published" || !validID(data.MetricID) || strings.TrimSpace(data.Version) == "" || row.ID != data.MetricID+"."+data.Version {
		return MetricSnapshot{}, snapshotInvalid("metric %q identity or status mismatch", row.ID)
	}
	if err := validateMetric(data); err != nil {
		return MetricSnapshot{}, snapshotInvalid("metric %q is invalid: %v", row.ID, err)
	}
	actualHash, err := contentHash(data.Formula)
	if err != nil || !validSHA256(data.FormulaHash) || actualHash != data.FormulaHash || data.FormulaHash != reference.FormulaHash {
		return MetricSnapshot{}, snapshotInvalid("metric %q formula hash mismatch", row.ID)
	}
	if data.PluginID != reference.PluginID || data.PluginVersion != reference.PluginVersion || data.PluginDigest != reference.PluginDigest {
		return MetricSnapshot{}, snapshotInvalid("metric %q plugin binding differs from suite snapshot", row.ID)
	}
	return MetricSnapshot{ID: row.ID, Revision: row.Revision, MetricID: data.MetricID, Version: data.Version, Name: data.Name, Kind: data.Kind, PluginID: data.PluginID, PluginVersion: data.PluginVersion, PluginDigest: data.PluginDigest, Formula: append(json.RawMessage(nil), data.Formula...), FormulaHash: data.FormulaHash}, nil
}

func decodeSnapshotJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxBodySize || !json.Valid(raw) {
		return errors.New("empty, oversized, or malformed JSON")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeJSONUseNumber(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxBodySize || !json.Valid(raw) {
		return errors.New("empty, oversized, or malformed JSON")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func snapshotInvalid(format string, args ...any) error {
	return fmt.Errorf(format+": %w", append(args, ErrSnapshotInvalid)...)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func sameOrderedStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func cloneRawMessages(items []json.RawMessage) []json.RawMessage {
	clone := make([]json.RawMessage, len(items))
	for i := range items {
		clone[i] = append(json.RawMessage(nil), items[i]...)
	}
	return clone
}
