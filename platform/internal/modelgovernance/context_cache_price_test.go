package modelgovernance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestCachePriceApprovalAndLegacyHashCompatibility(t *testing.T) {
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	input := CreatePriceVersionRequest{ModelVersionID: "version-price", Currency: "USD", InputMicrosPer1K: 400, OutputMicrosPer1K: 800, EffectiveFrom: start}
	legacy, err := normalizeCreatePriceRequest(input)
	if err != nil || assignPriceContentHash(&legacy) != nil {
		t.Fatal(err)
	}
	// Independent released canonical payload; the new nil field must not alter it.
	raw := []byte(`{"model_version_id":"version-price","currency":"USD","input_micros_per_1k_tokens":400,"output_micros_per_1k_tokens":800,"effective_from":"2030-01-01T00:00:00Z"}`)
	digest := sha256.Sum256(raw)
	if legacy.ContentHash != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("historical price hash changed")
	}
	for _, rate := range []int64{-1, 401, 0, 100, 400} {
		store := newMemoryStore()
		seedApprovedPriceModel(store, TrustExternal, StatusApproved)
		module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
		body := fmt.Sprintf(`{"model_version_id":"version-price","currency":"USD","input_micros_per_1k_tokens":400,"output_micros_per_1k_tokens":800,"cached_input_micros_per_1k_tokens":%d,"effective_from":"2030-01-01T00:00:00Z"}`, rate)
		response := browserRequest(module.Handler(), http.MethodPost, "/prices", body, nil)
		if rate < 0 || rate > 400 {
			if response.Code != http.StatusBadRequest {
				t.Fatal("invalid cache tariff created", response.Code)
			}
			continue
		}
		if response.Code != http.StatusCreated {
			t.Fatalf("cache tariff rejected %d %s", response.Code, response.Body.String())
		}
		var row PriceVersion
		if json.Unmarshal(response.Body.Bytes(), &row) != nil || row.CachedInputMicrosPer1K == nil || *row.CachedInputMicrosPer1K != rate || row.ContentHash == legacy.ContentHash {
			t.Fatal("explicit zero/cached price lost")
		}
		response = browserRequest(module.Handler(), http.MethodPost, "/prices/"+row.ID+"/approve", `{"revision":1}`, nil)
		if response.Code != http.StatusOK {
			t.Fatal("cache price approval failed", response.Body.String())
		}
		resolved, err := store.ResolvePrice(context.Background(), "version-price", start.Add(time.Hour))
		if err != nil || resolved.CachedInputMicrosPer1K == nil || *resolved.CachedInputMicrosPer1K != rate {
			t.Fatal("approved cache price missing")
		}
	}
}

func TestPostgresContextCachePriceUpgradePreservesOldRowsAndExplicitZero(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_CONTEXT_CACHE_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated cache migration PostgreSQL fixture not configured")
	}
	ctx := context.Background()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("cache fixture connection: %T", err)
	}
	defer db.Close()
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil || !strings.HasPrefix(schema, "ctxcache_20261012_") {
		t.Fatal("dedicated registered cache test schema required")
	}
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("cc%d", time.Now().UnixNano())
	version := seedPostgresModel(t, store, key)
	old := PriceVersion{ID: key + "old", ModelVersionID: version, Currency: "USD", InputMicrosPer1K: 400, OutputMicrosPer1K: 800,
		EffectiveFrom: time.Now().UTC().Add(-time.Hour), Status: priceStatusDraft, Revision: 1, CreatedBy: "cache-test-publisher"}
	if assignPriceContentHash(&old) != nil {
		t.Fatal("cannot freeze original tariff")
	}
	if err := store.CreatePriceVersion(ctx, &old); err != nil {
		t.Fatal(err)
	}
	if err := store.ApprovePriceVersion(ctx, old.ID, 1); err != nil {
		t.Fatal(err)
	}
	// This schema is newly created exclusively for this test. Simulate the
	// previous released table after saving a genuine old price through its port.
	if _, err := db.ExecContext(ctx, "ALTER TABLE platform_model_price_version DROP COLUMN cached_input_micros_per_1k_tokens"); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := store.GetPriceVersion(ctx, old.ID)
	if err != nil || before.CachedInputMicrosPer1K != nil || before.ContentHash != old.ContentHash || before.Status != StatusApproved {
		t.Fatal("legacy tariff changed on upgrade", err)
	}
	zero := int64(0)
	newRow := old
	newRow.ID, newRow.ModelVersionID = key+"new", seedPostgresModel(t, store, key+"n")
	newRow.CachedInputMicrosPer1K = &zero
	newRow.Status, newRow.Revision = priceStatusDraft, 1
	if assignPriceContentHash(&newRow) != nil {
		t.Fatal("cannot freeze cache tariff")
	}
	if err := store.CreatePriceVersion(ctx, &newRow); err != nil {
		t.Fatal(err)
	}
	if err := store.ApprovePriceVersion(ctx, newRow.ID, 1); err != nil {
		t.Fatal(err)
	}
	observed, err := NewSQLStore(db).ResolvePrice(ctx, newRow.ModelVersionID, time.Now().UTC())
	if err != nil || observed.CachedInputMicrosPer1K == nil || *observed.CachedInputMicrosPer1K != 0 || observed.ContentHash != newRow.ContentHash {
		t.Fatal("explicit zero cache price did not persist", err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind("UPDATE platform_model_price_version SET cached_input_micros_per_1k_tokens=401 WHERE id=?"), newRow.ID); sqlutil.SQLState(err) != "23514" {
		t.Fatal("database accepted cache rate above ordinary input", err)
	}
}
