package modelgovernance

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
)

type metadataScript func(string, []driver.NamedValue) ([]driver.Value, bool, error)

type metadataConnector struct{ script metadataScript }

func (c metadataConnector) Connect(context.Context) (driver.Conn, error) {
	return metadataConn{script: c.script}, nil
}
func (c metadataConnector) Driver() driver.Driver { return metadataDriver{script: c.script} }

type metadataDriver struct{ script metadataScript }

func (d metadataDriver) Open(string) (driver.Conn, error) { return metadataConn{script: d.script}, nil }

type metadataConn struct{ script metadataScript }

func (c metadataConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("Prepare is not supported")
}
func (c metadataConn) Close() error { return nil }
func (c metadataConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}
func (c metadataConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values, found, err := c.script(query, args)
	if err != nil {
		return nil, err
	}
	columns := make([]string, len(values))
	for i := range columns {
		columns[i] = "column_" + string(rune('a'+i))
	}
	rows := &metadataRows{columns: columns}
	if found {
		rows.values = [][]driver.Value{values}
	}
	return rows, nil
}

type metadataRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *metadataRows) Columns() []string { return r.columns }
func (r *metadataRows) Close() error      { return nil }
func (r *metadataRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func TestSQLStoreImplementsApprovedMetadataPorts(t *testing.T) {
	store := scriptedMetadataStore(t, func(query string, _ []driver.NamedValue) ([]driver.Value, bool, error) {
		switch {
		case strings.Contains(query, "FROM platform_model_provider WHERE id=$1"):
			return []driver.Value{"provider-a", "local-provider", ProviderOnPrem, TrustLocal, "service://models", "secret://provider.key", StatusApproved}, true, nil
		case strings.Contains(query, "FROM platform_model_version mv"):
			return []driver.Value{"version-a", StatusApproved, "model-a", "provider-a", "chat-model", ModelKindChat, StatusDraft, "provider-a", StatusApproved}, true, nil
		default:
			return nil, false, errors.New("unexpected query")
		}
	})

	provider, err := store.GetApprovedProvider(context.Background(), "provider-a")
	if err != nil {
		t.Fatalf("approved provider resolution failed: %v", err)
	}
	if provider.ID != "provider-a" || provider.Key != "local-provider" || provider.EndpointRef != "service://models" || provider.SecretRef != "secret://provider.key" || provider.Status != StatusApproved {
		t.Fatalf("unexpected provider metadata: %+v", provider)
	}
	model, err := store.GetApprovedModel(context.Background(), "version-a")
	if err != nil {
		t.Fatalf("approved model resolution failed: %v", err)
	}
	if model.ID != "model-a" || model.VersionID != "version-a" || model.ProviderID != "provider-a" || model.Key != "chat-model" || model.Status != StatusApproved {
		t.Fatalf("unexpected model metadata: %+v", model)
	}
	var _ modelgateway.ProviderMetadataPort = store
	var _ modelgateway.ModelMetadataPort = store
}

func TestSQLStoreApprovedMetadataPortsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		values []driver.Value
	}{
		{name: "provider draft", query: "provider", values: []driver.Value{"provider-a", "local-provider", ProviderOnPrem, TrustLocal, "service://models", "secret://provider.key", StatusDraft}},
		{name: "provider trust mismatch", query: "provider", values: []driver.Value{"provider-a", "local-provider", ProviderExternalManaged, TrustLocal, "service://models", "secret://provider.key", StatusApproved}},
		{name: "provider arbitrary endpoint", query: "provider", values: []driver.Value{"provider-a", "local-provider", ProviderOnPrem, TrustLocal, "https://127.0.0.1", "secret://provider.key", StatusApproved}},
		{name: "model draft version", query: "model", values: []driver.Value{"version-a", StatusDraft, "model-a", "provider-a", "chat-model", ModelKindChat, StatusDraft, "provider-a", StatusApproved}},
		{name: "model disabled definition", query: "model", values: []driver.Value{"version-a", StatusApproved, "model-a", "provider-a", "chat-model", ModelKindChat, StatusDisabled, "provider-a", StatusApproved}},
		{name: "model provider disabled", query: "model", values: []driver.Value{"version-a", StatusApproved, "model-a", "provider-a", "chat-model", ModelKindChat, StatusDraft, "provider-a", StatusDisabled}},
		{name: "model provider relationship mismatch", query: "model", values: []driver.Value{"version-a", StatusApproved, "model-a", "provider-a", "chat-model", ModelKindChat, StatusDraft, "provider-b", StatusApproved}},
		{name: "model kind unsupported", query: "model", values: []driver.Value{"version-a", StatusApproved, "model-a", "provider-a", "chat-model", "completion_only", StatusDraft, "provider-a", StatusApproved}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := scriptedMetadataStore(t, func(query string, _ []driver.NamedValue) ([]driver.Value, bool, error) {
				if tc.query == "provider" && strings.Contains(query, "FROM platform_model_provider WHERE id=$1") || tc.query == "model" && strings.Contains(query, "FROM platform_model_version mv") {
					return tc.values, true, nil
				}
				return nil, false, errors.New("unexpected query")
			})
			if tc.query == "provider" {
				if _, err := store.GetApprovedProvider(context.Background(), "provider-a"); !errors.Is(err, ErrModelAccessDenied) {
					t.Fatalf("unsafe Provider metadata should fail closed, got %v", err)
				}
				return
			}
			if _, err := store.GetApprovedModel(context.Background(), "version-a"); !errors.Is(err, ErrModelAccessDenied) {
				t.Fatalf("unsafe Model metadata should fail closed, got %v", err)
			}
		})
	}

	t.Run("not found", func(t *testing.T) {
		store := scriptedMetadataStore(t, func(string, []driver.NamedValue) ([]driver.Value, bool, error) { return nil, false, nil })
		if _, err := store.GetApprovedProvider(context.Background(), "provider-a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing Provider should return not found, got %v", err)
		}
		if _, err := store.GetApprovedModel(context.Background(), "version-a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing Model should return not found, got %v", err)
		}
	})
}

func scriptedMetadataStore(t *testing.T, script metadataScript) *SQLStore {
	t.Helper()
	db := sql.OpenDB(metadataConnector{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return NewSQLStore(db)
}
