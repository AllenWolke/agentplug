package usagecost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"math"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidUsageQuery = errors.New("invalid usage query")
	ErrUsageForbidden    = errors.New("usage read forbidden")
)

const (
	DefaultUsagePageSize = 50
	MaxUsagePageSize     = 100
	MaxUsagePage         = 10000
)

type UsageAction string

const ActionReadUsage UsageAction = "read_usage"

// Actor is populated only from the trusted browser gateway headers. The
// injected Authorizer must check the current Identity roles and grants for the
// requested scope; a shared internal token alone does not authorize a browser.
type Actor struct {
	TenantID      string
	DepartmentID  string
	ApplicationID string
	PrincipalType string
	PrincipalID   string
}

type Authorizer interface {
	AuthorizeUsageCost(context.Context, Actor, UsageAction, Scope) error
}

// UsageAggregate is a time-bounded aggregate for the exact filter scope.
type UsageAggregate struct {
	Scope        Scope     `json:"scope"`
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	EventCount   int64     `json:"event_count"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	CostMicros   int64     `json:"cost_micros"`
}

type UsageEvent struct {
	Event     Event     `json:"event"`
	CreatedAt time.Time `json:"created_at"`
}

type UsageEventPage struct {
	Items    []UsageEvent `json:"items"`
	Total    int64        `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
}

// UsageRun is an execution summary grouped by its complete persisted Scope.
// Its usage interval describes the first and last cost events in the requested
// time range, not the full runtime trace interval.
type UsageRun struct {
	Scope        Scope     `json:"scope"`
	RunID        string    `json:"run_id"`
	FirstUsageAt time.Time `json:"first_usage_at"`
	LastUsageAt  time.Time `json:"last_usage_at"`
	EventCount   int64     `json:"event_count"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	CostMicros   int64     `json:"cost_micros"`
}

type UsageRunPage struct {
	Items    []UsageRun `json:"items"`
	Total    int64      `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
}

// UsageStep represents one ordered UsageCost event within a run. It is a
// billing step, not a claim that every runtime tool/knowledge step is recorded.
type UsageStep struct {
	Index        int64     `json:"index"`
	EventID      string    `json:"event_id"`
	StepID       *string   `json:"step_id"`
	OccurredAt   time.Time `json:"occurred_at"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	CostMicros   int64     `json:"cost_micros"`
}

type UsageStepPage struct {
	Scope    Scope       `json:"scope"`
	From     time.Time   `json:"from"`
	To       time.Time   `json:"to"`
	Items    []UsageStep `json:"items"`
	Total    int64       `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

// UsageReader is an optional query extension. Store remains unchanged so
// existing internal writers and remote implementations keep their contract.
type UsageReader interface {
	AggregateUsage(context.Context, Scope, time.Time, time.Time) (UsageAggregate, error)
	ListUsageEvents(context.Context, Scope, time.Time, time.Time, int, int) (UsageEventPage, error)
}

type RunReader interface {
	ListRuns(context.Context, Scope, time.Time, time.Time, int, int) (UsageRunPage, error)
	ListRunSteps(context.Context, Scope, time.Time, time.Time, int, int) (UsageStepPage, error)
}

func validReadScope(scope Scope) bool {
	if strings.TrimSpace(scope.TenantID) == "" || strings.TrimSpace(scope.DepartmentID) == "" || strings.TrimSpace(scope.ApplicationID) == "" {
		return false
	}
	return true
}

func validateUsageRead(scope Scope, from, to time.Time) error {
	if !validReadScope(scope) || from.IsZero() || to.IsZero() || !from.Before(to) {
		return ErrInvalidUsageQuery
	}
	return nil
}

func validateUsagePage(page, pageSize int) error {
	if page < 1 || page > MaxUsagePage || pageSize < 1 || pageSize > MaxUsagePageSize {
		return ErrInvalidUsageQuery
	}
	return nil
}

func usageWhere(scope Scope, from, to time.Time) (string, []any) {
	where := `tenant_id=? AND department_id=? AND application_id=? AND created_at>=? AND created_at<?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, from.UTC(), to.UTC()}
	if scope.AgentID != "" {
		where += ` AND agent_id=?`
		args = append(args, scope.AgentID)
	}
	if scope.AgentVersionID != "" {
		where += ` AND agent_version_id=?`
		args = append(args, scope.AgentVersionID)
	}
	if scope.RunID != "" {
		where += ` AND run_id=?`
		args = append(args, scope.RunID)
	}
	return where, args
}

func (s *SQLStore) AggregateUsage(ctx context.Context, scope Scope, from, to time.Time) (UsageAggregate, error) {
	if s == nil || s.db == nil {
		return UsageAggregate{}, errors.New("usage database is required")
	}
	if err := validateUsageRead(scope, from, to); err != nil {
		return UsageAggregate{}, err
	}
	where, args := usageWhere(scope, from, to)
	result := UsageAggregate{Scope: scope, From: from.UTC(), To: to.UTC()}
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(cost_micros),0) FROM platform_usage_event WHERE `+where), args...).Scan(
		&result.EventCount, &result.InputTokens, &result.OutputTokens, &result.CostMicros)
	if err != nil {
		return UsageAggregate{}, fmt.Errorf("aggregate usage events: %w", err)
	}
	return result, nil
}

func (s *SQLStore) ListUsageEvents(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageEventPage, error) {
	if s == nil || s.db == nil {
		return UsageEventPage{}, errors.New("usage database is required")
	}
	if err := validateUsageRead(scope, from, to); err != nil {
		return UsageEventPage{}, err
	}
	if err := validateUsagePage(page, pageSize); err != nil {
		return UsageEventPage{}, err
	}
	where, args := usageWhere(scope, from, to)
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_usage_event WHERE `+where), args...).Scan(&total); err != nil {
		return UsageEventPage{}, fmt.Errorf("count usage events: %w", err)
	}
	queryArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT event_id,tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,provider,model,input_tokens,output_tokens,cost_micros,step_id,created_at FROM platform_usage_event WHERE `+where+` ORDER BY created_at DESC,event_id DESC LIMIT ? OFFSET ?`), queryArgs...)
	if err != nil {
		return UsageEventPage{}, fmt.Errorf("list usage events: %w", err)
	}
	defer rows.Close()
	items := make([]UsageEvent, 0, pageSize)
	for rows.Next() {
		var item UsageEvent
		var stepID sql.NullString
		if err := rows.Scan(&item.Event.ID, &item.Event.Scope.TenantID, &item.Event.Scope.DepartmentID, &item.Event.Scope.ApplicationID, &item.Event.Scope.AgentID, &item.Event.Scope.AgentVersionID, &item.Event.Scope.RunID, &item.Event.Provider, &item.Event.Model, &item.Event.InputTokens, &item.Event.OutputTokens, &item.Event.CostMicros, &stepID, &item.CreatedAt); err != nil {
			return UsageEventPage{}, fmt.Errorf("scan usage event: %w", err)
		}
		if stepID.Valid {
			item.Event.StepID = &stepID.String
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return UsageEventPage{}, fmt.Errorf("iterate usage events: %w", err)
	}
	return UsageEventPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *SQLStore) ListRuns(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageRunPage, error) {
	if s == nil || s.db == nil {
		return UsageRunPage{}, errors.New("usage database is required")
	}
	if err := validateUsageRead(scope, from, to); err != nil {
		return UsageRunPage{}, err
	}
	if err := validateUsagePage(page, pageSize); err != nil {
		return UsageRunPage{}, err
	}
	where, args := usageWhere(scope, from, to)
	group := `tenant_id,department_id,application_id,agent_id,agent_version_id,run_id`
	var total int64
	countQuery := `SELECT COUNT(*) FROM (SELECT ` + group + ` FROM platform_usage_event WHERE ` + where + ` GROUP BY ` + group + `) AS scoped_runs`
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(countQuery), args...).Scan(&total); err != nil {
		return UsageRunPage{}, fmt.Errorf("count usage runs: %w", err)
	}
	queryArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	query := `SELECT tenant_id,department_id,application_id,agent_id,agent_version_id,run_id,MIN(created_at),MAX(created_at),COUNT(*),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(cost_micros),0) FROM platform_usage_event WHERE ` + where + ` GROUP BY ` + group + ` ORDER BY MAX(created_at) DESC,run_id DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), queryArgs...)
	if err != nil {
		return UsageRunPage{}, fmt.Errorf("list usage runs: %w", err)
	}
	defer rows.Close()
	items := make([]UsageRun, 0, pageSize)
	for rows.Next() {
		var item UsageRun
		if err := rows.Scan(&item.Scope.TenantID, &item.Scope.DepartmentID, &item.Scope.ApplicationID, &item.Scope.AgentID, &item.Scope.AgentVersionID, &item.Scope.RunID, &item.FirstUsageAt, &item.LastUsageAt, &item.EventCount, &item.InputTokens, &item.OutputTokens, &item.CostMicros); err != nil {
			return UsageRunPage{}, fmt.Errorf("scan usage run: %w", err)
		}
		item.RunID = item.Scope.RunID
		item.FirstUsageAt = item.FirstUsageAt.UTC()
		item.LastUsageAt = item.LastUsageAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return UsageRunPage{}, fmt.Errorf("iterate usage runs: %w", err)
	}
	return UsageRunPage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *SQLStore) ListRunSteps(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageStepPage, error) {
	if s == nil || s.db == nil {
		return UsageStepPage{}, errors.New("usage database is required")
	}
	if err := validateUsageRead(scope, from, to); err != nil || scope.RunID == "" {
		return UsageStepPage{}, ErrInvalidUsageQuery
	}
	if err := validateUsagePage(page, pageSize); err != nil {
		return UsageStepPage{}, err
	}
	where, args := usageWhere(scope, from, to)
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_usage_event WHERE `+where), args...).Scan(&total); err != nil {
		return UsageStepPage{}, fmt.Errorf("count usage run steps: %w", err)
	}
	queryArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	query := `SELECT event_id,step_id,created_at,provider,model,input_tokens,output_tokens,cost_micros FROM platform_usage_event WHERE ` + where + ` ORDER BY created_at ASC,event_id ASC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), queryArgs...)
	if err != nil {
		return UsageStepPage{}, fmt.Errorf("list usage run steps: %w", err)
	}
	defer rows.Close()
	items := make([]UsageStep, 0, pageSize)
	for rows.Next() {
		var item UsageStep
		var stepID sql.NullString
		if err := rows.Scan(&item.EventID, &stepID, &item.OccurredAt, &item.Provider, &item.Model, &item.InputTokens, &item.OutputTokens, &item.CostMicros); err != nil {
			return UsageStepPage{}, fmt.Errorf("scan usage run step: %w", err)
		}
		if stepID.Valid {
			item.StepID = &stepID.String
		}
		item.Index = int64((page-1)*pageSize + len(items) + 1)
		item.OccurredAt = item.OccurredAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return UsageStepPage{}, fmt.Errorf("iterate usage run steps: %w", err)
	}
	return UsageStepPage{Scope: scope, From: from.UTC(), To: to.UTC(), Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (l *Ledger) AggregateUsage(ctx context.Context, scope Scope, from, to time.Time) (UsageAggregate, error) {
	if err := validateUsageRead(scope, from, to); err != nil {
		return UsageAggregate{}, err
	}
	if err := ctx.Err(); err != nil {
		return UsageAggregate{}, err
	}
	result := UsageAggregate{Scope: scope, From: from.UTC(), To: to.UTC()}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, event := range l.events {
		created := l.createdAt[id]
		if !usageScopeMatches(scope, event.Scope) || created.Before(from) || !created.Before(to) {
			continue
		}
		if result.EventCount == math.MaxInt64 || event.InputTokens > math.MaxInt64-result.InputTokens || event.OutputTokens > math.MaxInt64-result.OutputTokens || event.CostMicros > math.MaxInt64-result.CostMicros {
			return UsageAggregate{}, ErrInvalidUsage
		}
		result.EventCount++
		result.InputTokens += event.InputTokens
		result.OutputTokens += event.OutputTokens
		result.CostMicros += event.CostMicros
	}
	return result, nil
}

func (l *Ledger) ListUsageEvents(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageEventPage, error) {
	if err := validateUsageRead(scope, from, to); err != nil {
		return UsageEventPage{}, err
	}
	if err := validateUsagePage(page, pageSize); err != nil {
		return UsageEventPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return UsageEventPage{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	all := make([]UsageEvent, 0)
	for id, event := range l.events {
		created := l.createdAt[id]
		if usageScopeMatches(scope, event.Scope) && !created.Before(from) && created.Before(to) {
			event.StepID = cloneStepID(event.StepID)
			all = append(all, UsageEvent{Event: event, CreatedAt: created.UTC()})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].Event.ID > all[j].Event.ID
		}
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})
	total := int64(len(all))
	offset := (page - 1) * pageSize
	if offset >= len(all) {
		all = []UsageEvent{}
	} else {
		end := offset + pageSize
		if end > len(all) {
			end = len(all)
		}
		all = all[offset:end]
	}
	return UsageEventPage{Items: all, Total: total, Page: page, PageSize: pageSize}, nil
}

func (l *Ledger) ListRuns(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageRunPage, error) {
	if err := validateUsageRead(scope, from, to); err != nil {
		return UsageRunPage{}, err
	}
	if err := validateUsagePage(page, pageSize); err != nil {
		return UsageRunPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return UsageRunPage{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	runs := make(map[Scope]UsageRun)
	for id, event := range l.events {
		created := l.createdAt[id]
		if !usageScopeMatches(scope, event.Scope) || created.Before(from) || !created.Before(to) {
			continue
		}
		run := runs[event.Scope]
		if run.EventCount == 0 {
			run.Scope = event.Scope
			run.RunID = event.Scope.RunID
			run.FirstUsageAt = created.UTC()
			run.LastUsageAt = created.UTC()
		}
		if created.Before(run.FirstUsageAt) {
			run.FirstUsageAt = created.UTC()
		}
		if created.After(run.LastUsageAt) {
			run.LastUsageAt = created.UTC()
		}
		run.EventCount++
		run.InputTokens += event.InputTokens
		run.OutputTokens += event.OutputTokens
		run.CostMicros += event.CostMicros
		runs[event.Scope] = run
	}
	all := make([]UsageRun, 0, len(runs))
	for _, run := range runs {
		all = append(all, run)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].LastUsageAt.Equal(all[j].LastUsageAt) {
			return all[i].RunID > all[j].RunID
		}
		return all[i].LastUsageAt.After(all[j].LastUsageAt)
	})
	total := int64(len(all))
	offset := (page - 1) * pageSize
	if offset >= len(all) {
		all = []UsageRun{}
	} else {
		end := offset + pageSize
		if end > len(all) {
			end = len(all)
		}
		all = all[offset:end]
	}
	return UsageRunPage{Items: all, Total: total, Page: page, PageSize: pageSize}, nil
}

func (l *Ledger) ListRunSteps(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageStepPage, error) {
	if err := validateUsageRead(scope, from, to); err != nil || scope.RunID == "" {
		return UsageStepPage{}, ErrInvalidUsageQuery
	}
	if err := validateUsagePage(page, pageSize); err != nil {
		return UsageStepPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return UsageStepPage{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	all := make([]UsageStep, 0)
	for id, event := range l.events {
		created := l.createdAt[id]
		if !usageScopeMatches(scope, event.Scope) || created.Before(from) || !created.Before(to) {
			continue
		}
		all = append(all, UsageStep{EventID: event.ID, StepID: cloneStepID(event.StepID), OccurredAt: created.UTC(), Provider: event.Provider, Model: event.Model, InputTokens: event.InputTokens, OutputTokens: event.OutputTokens, CostMicros: event.CostMicros})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].OccurredAt.Equal(all[j].OccurredAt) {
			return all[i].EventID < all[j].EventID
		}
		return all[i].OccurredAt.Before(all[j].OccurredAt)
	})
	total := int64(len(all))
	offset := (page - 1) * pageSize
	if offset >= len(all) {
		all = []UsageStep{}
	} else {
		end := offset + pageSize
		if end > len(all) {
			end = len(all)
		}
		all = all[offset:end]
		for i := range all {
			all[i].Index = int64(offset + i + 1)
		}
	}
	return UsageStepPage{Scope: scope, From: from.UTC(), To: to.UTC(), Items: all, Total: total, Page: page, PageSize: pageSize}, nil
}

func usageScopeMatches(filter, actual Scope) bool {
	return filter.TenantID == actual.TenantID && filter.DepartmentID == actual.DepartmentID && filter.ApplicationID == actual.ApplicationID &&
		(filter.AgentID == "" || filter.AgentID == actual.AgentID) &&
		(filter.AgentVersionID == "" || filter.AgentVersionID == actual.AgentVersionID) &&
		(filter.RunID == "" || filter.RunID == actual.RunID)
}

var _ UsageReader = (*SQLStore)(nil)
var _ UsageReader = (*Ledger)(nil)
var _ RunReader = (*SQLStore)(nil)
var _ RunReader = (*Ledger)(nil)
