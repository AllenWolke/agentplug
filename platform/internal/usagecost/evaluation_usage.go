package usagecost

import (
	"context"
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
}

// 同一语句快照读取用量、未结算预占及历史价目证明；不推断提供商账单。
func (s *SQLStore) EvaluationUsage(ctx context.Context, scope Scope, from, to time.Time) (EvaluationUsageSummary, error) {
	var result EvaluationUsageSummary
	if s == nil || s.db == nil || scope.AgentID == "" || scope.AgentVersionID == "" || scope.RunID == "" || validateUsageRead(scope, from, to) != nil {
		return result, errors.New("scoped evaluation usage query required")
	}
	params := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, scope.RunID, from.UTC(), to.UTC()}
	params = append(params, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, scope.RunID)
	result.Scope, result.From, result.To = scope, from.UTC(), to.UTC()
	var currencyCount int64
	var currency string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`WITH scoped_events AS (
SELECT event_id,input_tokens,output_tokens,cost_micros FROM platform_usage_event
WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? AND created_at>=? AND created_at<?
), priced_events AS (
SELECT e.*,(SELECT CASE WHEN COUNT(*)=1 THEN MAX(p.currency) ELSE NULL END
FROM platform_model_budget_settlement st JOIN platform_model_price_version p ON p.id=st.price_version_id
WHERE st.event_id=e.event_id AND st.settled_micros=e.cost_micros) AS currency FROM scoped_events e
)
SELECT COUNT(*),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),
CASE WHEN COUNT(currency)=COUNT(*) AND COUNT(DISTINCT currency)=1 THEN COALESCE(SUM(cost_micros),0) ELSE 0 END,
(SELECT COUNT(*) FROM platform_model_budget_reservation WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? AND status NOT IN ('settled','released')),
COUNT(*)-COUNT(currency),COUNT(DISTINCT currency),COALESCE(MIN(currency),'') FROM priced_events`), params...).Scan(
		&result.EventCount, &result.InputTokens, &result.OutputTokens, &result.CostMicros, &result.Unsettled, &result.Unpriced, &currencyCount, &currency)
	if err == nil && result.EventCount > 0 && result.Unpriced == 0 && currencyCount == 1 && regexp.MustCompile(`^[A-Z]{3}$`).MatchString(currency) {
		result.Currency = currency
	}
	return result, err
}
