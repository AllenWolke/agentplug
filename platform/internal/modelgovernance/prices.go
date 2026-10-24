package modelgovernance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const priceStatusDraft = "draft"

type priceHashPayload struct {
	ModelVersionID         string     `json:"model_version_id"`
	Currency               string     `json:"currency"`
	InputMicrosPer1K       int64      `json:"input_micros_per_1k_tokens"`
	OutputMicrosPer1K      int64      `json:"output_micros_per_1k_tokens"`
	EffectiveFrom          time.Time  `json:"effective_from"`
	EffectiveUntil         *time.Time `json:"effective_until,omitempty"`
	CachedInputMicrosPer1K *int64     `json:"cached_input_micros_per_1k_tokens,omitempty"`
}

func normalizeCreatePriceRequest(in CreatePriceVersionRequest) (PriceVersion, error) {
	row := PriceVersion{
		ModelVersionID:         strings.TrimSpace(in.ModelVersionID),
		Currency:               strings.ToUpper(strings.TrimSpace(in.Currency)),
		InputMicrosPer1K:       in.InputMicrosPer1K,
		CachedInputMicrosPer1K: cloneCachePrice(in.CachedInputMicrosPer1K),
		OutputMicrosPer1K:      in.OutputMicrosPer1K,
		EffectiveFrom:          in.EffectiveFrom.UTC(),
		EffectiveUntil:         in.EffectiveUntil,
		Status:                 priceStatusDraft,
		Revision:               1,
	}
	if row.EffectiveUntil != nil {
		until := row.EffectiveUntil.UTC()
		row.EffectiveUntil = &until
	}
	if err := validatePriceFields(&row); err != nil {
		return PriceVersion{}, err
	}
	return row, nil
}

func validatePriceVersion(row *PriceVersion) error {
	if err := validatePriceFields(row); err != nil {
		return err
	}
	if row.ID == "" || len(row.ID) > 128 || row.Status != priceStatusDraft || row.Revision != 1 || row.CreatedBy == "" || len(row.CreatedBy) > 128 || len(row.ContentHash) != 71 || !strings.HasPrefix(row.ContentHash, "sha256:") {
		return ErrInvalidRequest
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(row.ContentHash, "sha256:")); err != nil {
		return ErrInvalidRequest
	}
	copy := *row
	if err := assignPriceContentHash(&copy); err != nil || copy.ContentHash != row.ContentHash {
		return ErrInvalidRequest
	}
	return nil
}

func validatePriceFields(row *PriceVersion) error {
	if row == nil || row.ModelVersionID == "" || len(row.ModelVersionID) > 128 || len(row.Currency) != 3 || row.Currency != strings.ToUpper(row.Currency) ||
		!isASCIILetters(row.Currency) || row.InputMicrosPer1K < 0 || row.OutputMicrosPer1K < 0 || row.EffectiveFrom.IsZero() ||
		(row.EffectiveUntil != nil && !row.EffectiveUntil.After(row.EffectiveFrom)) {
		return ErrInvalidRequest
	}
	if row.CachedInputMicrosPer1K != nil && (*row.CachedInputMicrosPer1K < 0 || *row.CachedInputMicrosPer1K > row.InputMicrosPer1K) {
		return ErrInvalidRequest
	}
	return nil
}

func cloneCachePrice(rate *int64) *int64 {
	if rate == nil {
		return nil
	}
	value := *rate
	return &value
}

const priceColumns = `id,model_version_id,currency,input_micros_per_1k_tokens,output_micros_per_1k_tokens,effective_from,effective_until,content_hash,status,revision,created_by,created_at,updated_at,cached_input_micros_per_1k_tokens`

func scanPriceVersion(scanner interface{ Scan(...any) error }) (PriceVersion, error) {
	var row PriceVersion
	var effectiveUntil sql.NullTime
	var cachedRate sql.NullInt64
	err := scanner.Scan(&row.ID, &row.ModelVersionID, &row.Currency, &row.InputMicrosPer1K, &row.OutputMicrosPer1K, &row.EffectiveFrom, &effectiveUntil, &row.ContentHash, &row.Status, &row.Revision, &row.CreatedBy, &row.CreatedAt, &row.UpdatedAt, &cachedRate)
	if cachedRate.Valid {
		row.CachedInputMicrosPer1K = &cachedRate.Int64
	}
	if effectiveUntil.Valid {
		row.EffectiveUntil = &effectiveUntil.Time
	}
	return row, mapNotFound(err)
}

func isASCIILetters(value string) bool {
	for _, r := range value {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func validatePriceRates(trustZone, kind string, input, output int64) error {
	if (trustZone != TrustLocal && trustZone != TrustPrivate && trustZone != TrustExternal) || input < 0 || output < 0 || (kind != ModelKindChat && kind != ModelKindEmbedding) {
		return ErrInvalidRequest
	}
	// Embedding has no generated output tokens. A zero output rate is valid,
	// while missing external input pricing and free external chat remain invalid.
	if trustZone == TrustExternal && (input == 0 || (kind == ModelKindChat && output == 0)) {
		return ErrInvalidRequest
	}
	return nil
}

func assignPriceContentHash(row *PriceVersion) error {
	payload := priceHashPayload{
		ModelVersionID: row.ModelVersionID, Currency: row.Currency,
		InputMicrosPer1K: row.InputMicrosPer1K, OutputMicrosPer1K: row.OutputMicrosPer1K,
		CachedInputMicrosPer1K: row.CachedInputMicrosPer1K,
		EffectiveFrom:          row.EffectiveFrom.UTC(), EffectiveUntil: row.EffectiveUntil,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	row.ContentHash = "sha256:" + hex.EncodeToString(digest[:])
	return nil
}

func priceIntervalsOverlap(a, b PriceVersion) bool {
	if a.ModelVersionID != b.ModelVersionID {
		return false
	}
	if a.EffectiveUntil != nil && !a.EffectiveUntil.After(b.EffectiveFrom) {
		return false
	}
	if b.EffectiveUntil != nil && !b.EffectiveUntil.After(a.EffectiveFrom) {
		return false
	}
	return true
}

func (m *Module) prices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := m.authorizePriceAdmin(w, r, ActionRead); !ok {
			return
		}
		limit, ok := readLimit(w, r)
		if !ok {
			return
		}
		modelVersionID := strings.TrimSpace(r.URL.Query().Get("model_version_id"))
		if len(modelVersionID) > 128 {
			m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "model_version_id is too long")
			return
		}
		rows, err := m.store.ListPriceVersions(r.Context(), modelVersionID, limit)
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"items": rows})
	case http.MethodPost:
		actor, ok := m.authorizePriceAdmin(w, r, ActionCreate)
		if !ok {
			return
		}
		var in CreatePriceVersionRequest
		if !m.decode(w, r, &in) {
			return
		}
		row, err := normalizeCreatePriceRequest(in)
		if err != nil {
			m.storeError(w, err)
			return
		}
		resolved, err := m.store.GetResolvedVersion(r.Context(), row.ModelVersionID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if resolved.VersionStatus != StatusApproved || resolved.ProviderStatus != StatusApproved {
			m.error(w, http.StatusConflict, "MODEL_VERSION_NOT_APPROVED", "price requires an approved model version and provider")
			return
		}
		if err = validatePriceRates(resolved.TrustZone, resolved.Kind, row.InputMicrosPer1K, row.OutputMicrosPer1K); err != nil {
			m.storeError(w, err)
			return
		}
		if row.CachedInputMicrosPer1K != nil && resolved.Kind != ModelKindChat {
			m.storeError(w, ErrInvalidRequest)
			return
		}
		row.ID, err = newID()
		if err != nil {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not allocate model price id")
			return
		}
		row.CreatedBy = actor.PrincipalID
		if err = assignPriceContentHash(&row); err != nil {
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "could not hash model price")
			return
		}
		if err = m.store.CreatePriceVersion(r.Context(), &row); err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusCreated, row)
	default:
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
	}
}

func (m *Module) price(w http.ResponseWriter, r *http.Request) {
	parts := pathParts(r.URL.Path, "/prices/")
	if len(parts) == 0 || parts[0] == "" {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		if _, ok := m.authorizePriceAdmin(w, r, ActionRead); !ok {
			return
		}
		row, err := m.store.GetPriceVersion(r.Context(), parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		m.json(w, http.StatusOK, row)
		return
	}
	if len(parts) != 2 || parts[1] != "approve" || r.Method != http.MethodPost {
		m.error(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return
	}
	if _, ok := m.authorizePriceAdmin(w, r, ActionApprove); !ok {
		return
	}
	var in struct {
		Revision uint64 `json:"revision"`
	}
	if !m.decode(w, r, &in) {
		return
	}
	if in.Revision == 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "positive revision is required")
		return
	}
	if err := m.store.ApprovePriceVersion(r.Context(), parts[0], in.Revision); err != nil {
		m.storeError(w, err)
		return
	}
	row, err := m.store.GetPriceVersion(r.Context(), parts[0])
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, row)
}

func (m *Module) authorizePriceAdmin(w http.ResponseWriter, r *http.Request, action Action) (Actor, bool) {
	actor, ok := m.authorize(w, r, action)
	if !ok {
		return Actor{}, false
	}
	if !actor.Browser {
		m.error(w, http.StatusForbidden, "FORBIDDEN", "platform administrator browser identity is required for price catalog operations")
		return Actor{}, false
	}
	return actor, true
}
