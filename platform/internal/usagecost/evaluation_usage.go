package usagecost

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"regexp"
	"time"
)

type EvaluationUsageSummary struct {
	UsageAggregate
	Unsettled int64  `json:"unsettled"`
	Unpriced  int64  `json:"unpriced"`
	Currency  string `json:"currency,omitempty"`
	// Internal exact-step evidence, read in the same ledger snapshot. It is
	// not an application-wide usage HTTP contract or a historical backfill.
	ModelUsageStepIDs       []string `json:"-"`
	ModelUsageLinksComplete bool     `json:"-"`
}

// EvaluationPriceCurrencyReader 由价目所有者核验历史事实；用量读取方保持
// 同一只读快照，避免费用、结算和币种来自三个不同时间点。
type EvaluationPriceCurrencyReader interface {
	HistoricalPriceCurrencyTx(context.Context, *sql.Tx, string) (string, error)
}

func (s *SQLStore) SetEvaluationPriceCurrencyReader(reader EvaluationPriceCurrencyReader) error {
	if s == nil || reader == nil || s.priceCurrency != nil {
		return ErrInvalidUsage
	}
	s.priceCurrency = reader
	return nil
}

var evaluationCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

// EvaluationUsage 在同一快照内读取本模块账本，通过事务端口核验历史
// 价目。未知费用或混合币种不形成一个可相加的金额。
func (s *SQLStore) EvaluationUsage(ctx context.Context, scope Scope, from, to time.Time) (EvaluationUsageSummary, error) {
	var result EvaluationUsageSummary
	if s == nil || s.db == nil || scope.AgentID == "" || scope.AgentVersionID == "" || scope.RunID == "" || validateUsageRead(scope, from, to) != nil {
		return result, errors.New("scoped evaluation usage query required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	params := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, scope.RunID, from.UTC(), to.UTC()}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`WITH scoped_events AS (
 SELECT event_id,input_tokens,output_tokens,cost_micros FROM platform_usage_event
 WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? AND created_at>=? AND created_at<?
), priced_events AS (
 SELECT e.*,(SELECT CASE WHEN COUNT(*)=1 THEN MAX(st.price_version_id) ELSE NULL END
 FROM platform_model_budget_settlement st
 WHERE st.event_id=e.event_id AND st.settled_micros=e.cost_micros) AS price_id FROM scoped_events e
)
SELECT price_id,COUNT(*),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(cost_micros),0)
FROM priced_events GROUP BY price_id`), params...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	type group struct {
		id                          sql.NullString
		events, input, output, cost int64
	}
	var groups []group
	for rows.Next() {
		var g group
		if err = rows.Scan(&g.id, &g.events, &g.input, &g.output, &g.cost); err != nil {
			return result, err
		}
		groups = append(groups, g)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if err = rows.Close(); err != nil {
		return result, err
	}
	result.Scope, result.From, result.To = scope, from.UTC(), to.UTC()
	var cost int64
	currencies := make(map[string]bool)
	add := func(dst *int64, value int64) error {
		if value < 0 || *dst > maxInt64-value {
			return ErrInvalidUsage
		}
		*dst += value
		return nil
	}
	for _, g := range groups {
		for _, sum := range []struct {
			dst   *int64
			value int64
		}{{&result.EventCount, g.events}, {&result.InputTokens, g.input}, {&result.OutputTokens, g.output}, {&cost, g.cost}} {
			if err = add(sum.dst, sum.value); err != nil {
				return result, err
			}
		}
		if !g.id.Valid || g.id.String == "" {
			result.Unpriced += g.events
			continue
		}
		if s.priceCurrency == nil {
			return result, errors.New("historical price currency reader required")
		}
		currency, readErr := s.priceCurrency.HistoricalPriceCurrencyTx(ctx, tx, g.id.String)
		if readErr != nil {
			return result, readErr
		}
		if currency == "" {
			result.Unpriced += g.events
			continue
		}
		if !evaluationCurrencyPattern.MatchString(currency) {
			return result, ErrInvalidUsage
		}
		currencies[currency] = true
	}
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_model_budget_reservation WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? AND status NOT IN ('settled','released')`), params[:6]...).Scan(&result.Unsettled)
	if err != nil {
		return result, err
	}
	if result.EventCount > 0 && result.Unpriced == 0 && len(currencies) == 1 {
		for currency := range currencies {
			result.Currency = currency
		}
		result.CostMicros = cost
	}
	links, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT step_id FROM platform_usage_event
		WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? AND created_at>=? AND created_at<?
		ORDER BY event_id LIMIT 10001`), params...)
	if err != nil {
		return result, err
	}
	result.ModelUsageLinksComplete = true
	var linkedCount int64
	seenLinks := map[string]bool{}
	for links.Next() {
		var step sql.NullString
		if err = links.Scan(&step); err != nil {
			_ = links.Close()
			return result, err
		}
		linkedCount++
		if linkedCount > 10000 || !step.Valid || !evaluationModelStepPattern.MatchString(step.String) || seenLinks[step.String] {
			result.ModelUsageLinksComplete = false
			continue
		}
		seenLinks[step.String] = true
		result.ModelUsageStepIDs = append(result.ModelUsageStepIDs, step.String)
	}
	if err = links.Err(); err != nil {
		_ = links.Close()
		return result, err
	}
	if err = links.Close(); err != nil {
		return result, err
	}
	if linkedCount != result.EventCount {
		result.ModelUsageLinksComplete = false
	}
	if !result.ModelUsageLinksComplete {
		result.ModelUsageStepIDs = nil
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

var evaluationModelStepPattern = regexp.MustCompile(`^model-step-[0-9a-f]{64}$`)
