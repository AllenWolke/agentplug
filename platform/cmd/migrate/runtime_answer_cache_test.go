package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type runtimeAnswerCacheProof struct {
	Result                   string `json:"result"`
	ModelInvocationsBefore   int64  `json:"model_invocations_before_hit"`
	ModelInvocationsAfter    int64  `json:"model_invocations_after_hit"`
	BudgetReservationsBefore int64  `json:"budget_reservations_before_hit"`
	BudgetReservationsAfter  int64  `json:"budget_reservations_after_hit"`
	SavedInputTokens         int64  `json:"saved_input_tokens"`
	SavedOutputTokens        int64  `json:"saved_output_tokens"`
	TotalModelInvocations    int64  `json:"total_settled_model_invocations"`
	TotalInputTokens         int64  `json:"total_input_tokens"`
	TotalOutputTokens        int64  `json:"total_output_tokens"`
	TotalCostMicros          int64  `json:"total_cost_micros"`
	Scope                    string `json:"scope"`
}

// These fixtures query an ordinary execution Run whose verified TaskID is
// persisted verbatim by the production usage and model-budget ledgers.
func runtimeFixtureBillingRunID(run string) string {
	return run
}

// An owned test proxy reuses the live SDK's signed execution scope and workload
// credentials. It signs the new route with the fixture-only internal secret;
// all ordinary current SQL command/lease/IAM and provider checks still run.
func verifyRuntimeAnswerCache(parent *http.Request, body []byte, client *http.Client, address string, db *sql.DB, chat, embedding string) (runtimeAnswerCacheProof, error) {
	empty := runtimeAnswerCacheProof{}
	path := "/internal/knowledge/answer"
	call := func() ([]byte, error) {
		r, err := http.NewRequestWithContext(parent.Context(), http.MethodPost, "http://"+address+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header = parent.Header.Clone()
		digest := sha256.Sum256(body)
		material, _ := json.Marshal([]string{"platform-capability/v2", http.MethodPost, path, hex.EncodeToString(digest[:])})
		mac := hmac.New(sha256.New, []byte("fixture-signing-secret-with-32-bytes"))
		_, _ = mac.Write(material)
		r.Header.Set("X-Context-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		response, err := client.Do(r)
		if err != nil {
			return nil, errors.New("actual public answer request failed")
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err != nil || response.StatusCode != 200 || len(payload) > 1<<20 {
			return nil, errors.New("actual public answer endpoint rejected or exceeded limits")
		}
		return payload, nil
	}
	cold, err := call()
	if err != nil {
		return empty, err
	}
	var first struct {
		Data struct {
			Text string `json:"text"`
			Hit  bool   `json:"answer_cache_hit"`
		} `json:"data"`
	}
	if json.Unmarshal(cold, &first) != nil || first.Data.Text == "" || first.Data.Hit {
		return empty, errors.New("actual answer cold miss proof invalid")
	}
	before, input, output, cost, err := settledRuntimeModels(parent.Context(), db, chat, embedding)
	if err != nil || before != 5 {
		return empty, errors.New("actual answer miss did not settle one model invocation")
	}
	budget := func() (int64, int64, error) {
		return settledRuntimeBudgetForRun(parent.Context(), db, runtimeFixtureBillingRunID("go-process-run"))
	}
	budgetBefore, spentBefore, err := budget()
	if err != nil || budgetBefore != 4 {
		return empty, errors.New("actual answer budget miss proof invalid")
	}
	hot, err := call()
	if err != nil {
		return empty, err
	}
	after, afterInput, afterOutput, afterCost, err := settledRuntimeModels(parent.Context(), db, chat, embedding)
	if err != nil || after != before || afterInput != input || afterOutput != output || afterCost != cost {
		return empty, errors.New("actual answer cache hit changed the model ledger")
	}
	budgetAfter, spentAfter, err := budget()
	if err != nil || budgetAfter != budgetBefore || spentAfter != spentBefore {
		return empty, errors.New("actual answer cache hit changed the budget ledger")
	}
	var result struct {
		Data struct {
			Text   string `json:"text"`
			Hit    bool   `json:"answer_cache_hit"`
			Tokens struct {
				Input  int64 `json:"input_tokens"`
				Output int64 `json:"output_tokens"`
			} `json:"usage"`
			Billing struct {
				Cost int64 `json:"cost_micros"`
			} `json:"billing"`
			Saved struct {
				Input  int64 `json:"input_tokens"`
				Output int64 `json:"output_tokens"`
			} `json:"saved_usage"`
			Claims []struct {
				Text string `json:"text"`
			} `json:"evaluation_claims"`
		} `json:"data"`
	}
	if json.Unmarshal(hot, &result) != nil || !result.Data.Hit || result.Data.Text != first.Data.Text || result.Data.Tokens.Input != 0 || result.Data.Tokens.Output != 0 || result.Data.Billing.Cost != 0 || result.Data.Saved.Input != 20 || result.Data.Saved.Output != 10 || len(result.Data.Claims) != 1 || result.Data.Claims[0].Text != result.Data.Text {
		return empty, errors.New("actual answer cache or whole-answer evaluation receipt invalid")
	}
	return runtimeAnswerCacheProof{Result: "PASS", ModelInvocationsBefore: before, ModelInvocationsAfter: after, BudgetReservationsBefore: budgetBefore, BudgetReservationsAfter: budgetAfter, SavedInputTokens: result.Data.Saved.Input, SavedOutputTokens: result.Data.Saved.Output, Scope: "Actual platform Linux process/SQL command lease/caller-machine IAM/HMAC/SDK workload context/guarded loopback provider/approved-price invocation-budget-usage ledgers. Answer HTTP sent by owned test proxy while SDK run is live; not Python business or external supplier acceptance."}, nil
}
