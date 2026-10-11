package modelcapacity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type SQLProvider struct {
	db          *sql.DB
	now         func() time.Time
	deployments DeploymentReader
}

func NewSQLProvider(db *sql.DB) *SQLProvider {
	return &SQLProvider{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// SetDeploymentReader is composition-time wiring, before workers start.
// 只允许在 Worker 启动前由组合根接线，运行时不变更。
func (p *SQLProvider) SetDeploymentReader(reader DeploymentReader) {
	p.deployments = reader
}

func (p *SQLProvider) EnsureSchema(ctx context.Context) error {
	if p == nil || p.db == nil {
		return errors.New("model capacity database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_model_capacity_pool (
			deployment_id VARCHAR(36) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			department_id VARCHAR(64) NOT NULL,
			application_id VARCHAR(64) NOT NULL,
			model_version_id VARCHAR(36) NOT NULL,
			capacity_units BIGINT NOT NULL,
			reserved_units BIGINT NOT NULL DEFAULT 0,
			next_fencing_token BIGINT NOT NULL DEFAULT 0,
			health_status VARCHAR(24) NOT NULL,
			deployment_status VARCHAR(24) NOT NULL,
			revision BIGINT NOT NULL DEFAULT 1,
			updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_model_capacity_scope ON platform_model_capacity_pool (tenant_id,department_id,application_id,model_version_id);
CREATE INDEX IF NOT EXISTS idx_model_capacity_admission ON platform_model_capacity_pool (health_status,deployment_status);`,
		`CREATE TABLE IF NOT EXISTS platform_model_capacity_lease (
			id VARCHAR(32) PRIMARY KEY,
			deployment_id VARCHAR(36) NOT NULL,
			tenant_id VARCHAR(64) NOT NULL,
			department_id VARCHAR(64) NOT NULL,
			application_id VARCHAR(64) NOT NULL,
			units BIGINT NOT NULL,
			fencing_token BIGINT NOT NULL,
			owner VARCHAR(128) NOT NULL,
			request_id VARCHAR(128) NOT NULL,
			expires_at TIMESTAMPTZ(6) NOT NULL,
			status VARCHAR(16) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_model_capacity_fence UNIQUE (deployment_id,fencing_token));
CREATE INDEX IF NOT EXISTS idx_model_capacity_expiry ON platform_model_capacity_lease (status,expires_at);
CREATE INDEX IF NOT EXISTS idx_model_capacity_owner ON platform_model_capacity_lease (deployment_id,owner,status);`,
	}
	for _, statement := range statements {
		if _, err := p.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("model capacity schema: %w", err)
		}
	}
	return nil
}

// RegisterPoolTx creates the non-admitting capacity row in the same database
// transaction as its owning Model Deployment.
func RegisterPoolTx(tx *sql.Tx, deployment Deployment, at time.Time) error {
	if tx == nil || !validDeployment(deployment) {
		return ErrInvalid
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := tx.Exec(sqlutil.Bind(`INSERT INTO platform_model_capacity_pool (deployment_id,tenant_id,department_id,application_id,model_version_id,capacity_units,reserved_units,next_fencing_token,health_status,deployment_status,revision,updated_at) VALUES (?,?,?,?,?,?,0,0,'unknown','pending',1,?)`), deployment.ID, deployment.TenantID, deployment.DepartmentID, deployment.ApplicationID, deployment.ModelVersionID, deployment.CapacityUnits, at.UTC())
	return err
}

// UpdatePoolStateTx mirrors the Model Deployment health CAS inside that same
// transaction. Non-ready states stop new admission while existing leases may
// still release normally.
func UpdatePoolStateTx(tx *sql.Tx, scope sharedkernel.Scope, deploymentID, health, status string, at time.Time) error {
	if tx == nil || !validScope(scope) || deploymentID == "" || !validState(health, status) {
		return ErrInvalid
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	result, err := tx.Exec(sqlutil.Bind(`UPDATE platform_model_capacity_pool SET health_status=?,deployment_status=?,revision=revision+1,updated_at=? WHERE deployment_id=? AND tenant_id=? AND department_id=? AND application_id=?`), health, status, at.UTC(), deploymentID, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return err
	}
	return affectedOne(result)
}

func (p *SQLProvider) ResolveReadyDeployment(ctx context.Context, scope sharedkernel.Scope, modelVersionID string) (RuntimeDeployment, error) {
	if p == nil || p.db == nil || !validScope(scope) || strings.TrimSpace(modelVersionID) == "" {
		return RuntimeDeployment{}, ErrInvalid
	}
	if p.deployments == nil {
		return RuntimeDeployment{}, ErrUnavailable
	}
	rows, err := p.db.QueryContext(ctx, sqlutil.Bind(`SELECT deployment_id,model_version_id,capacity_units,health_status,deployment_status FROM platform_model_capacity_pool WHERE tenant_id=? AND department_id=? AND application_id=? AND model_version_id=? AND deployment_status=? AND health_status IN (?,?) ORDER BY deployment_id DESC LIMIT 2`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, modelVersionID, "ready", "ready", "degraded")
	if err != nil {
		return RuntimeDeployment{}, err
	}
	defer rows.Close()
	var result RuntimeDeployment
	count := 0
	for rows.Next() {
		if err = rows.Scan(&result.ID, &result.ModelVersionID, &result.CapacityUnits, &result.HealthStatus, &result.Status); err != nil {
			return RuntimeDeployment{}, err
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return RuntimeDeployment{}, err
	}
	if count != 1 {
		return RuntimeDeployment{}, ErrUnavailable
	}
	// Close the bounded query before calling another module (also safe with
	// a single DB connection). / 调用其他模块前释放连接，避免单连接池死锁。
	if err := rows.Close(); err != nil {
		return RuntimeDeployment{}, err
	}
	metadata, err := p.deployments.GetRuntimeDeployment(ctx, scope, result.ID)
	if err != nil {
		return RuntimeDeployment{}, err
	}
	if metadata.ID != result.ID || metadata.ModelVersionID != modelVersionID || metadata.CapacityUnits != result.CapacityUnits || metadata.Status != "ready" || (metadata.HealthStatus != "ready" && metadata.HealthStatus != "degraded") || strings.TrimSpace(metadata.EndpointRef) == "" {
		return RuntimeDeployment{}, ErrUnavailable
	}
	return metadata, nil
}

func (p *SQLProvider) AcquireCapacity(ctx context.Context, request Request) (Lease, error) {
	// PostgreSQL deadlocks and serialization failures require a whole-transaction retry.
	for attempt := 0; ; attempt++ {
		lease, err := p.acquireCapacityOnce(ctx, request)
		state := sqlutil.SQLState(err)
		if attempt >= 3 || (state != "40P01" && state != "40001") {
			return lease, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Lease{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *SQLProvider) acquireCapacityOnce(ctx context.Context, request Request) (Lease, error) {
	if p == nil || p.db == nil || request.Validate() != nil {
		return Lease{}, ErrInvalid
	}
	now := p.now().UTC()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, err
	}
	defer tx.Rollback()
	var capacity, reserved, nextFence, revision int64
	var health, status string
	scope := request.Scope
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT capacity_units,reserved_units,next_fencing_token,revision,health_status,deployment_status FROM platform_model_capacity_pool WHERE deployment_id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), request.DeploymentID, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&capacity, &reserved, &nextFence, &revision, &health, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, ErrUnavailable
	}
	if err != nil {
		return Lease{}, err
	}
	if !accepting(health, status) || capacity <= 0 || request.Units > capacity {
		return Lease{}, ErrUnavailable
	}
	if err = reapDeploymentTx(ctx, tx, request.DeploymentID, now, &reserved); err != nil {
		return Lease{}, err
	}
	if reserved < 0 || reserved+request.Units > capacity {
		return Lease{}, ErrExceeded
	}
	nextFence++
	reserved += request.Units
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_capacity_pool SET reserved_units=?,next_fencing_token=?,revision=revision+1,updated_at=? WHERE deployment_id=? AND revision=?`), reserved, nextFence, now, request.DeploymentID, revision)
	if err != nil {
		return Lease{}, err
	}
	if err = affectedOne(result); err != nil {
		return Lease{}, err
	}
	id, err := newID()
	if err != nil {
		return Lease{}, err
	}
	lease := Lease{ID: id, DeploymentID: request.DeploymentID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, Units: request.Units, FencingToken: nextFence, Owner: request.Owner, RequestID: request.RequestID, ExpiresAt: now.Add(request.TTL)}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_capacity_lease (id,deployment_id,tenant_id,department_id,application_id,units,fencing_token,owner,request_id,expires_at,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?, ?,?)`), lease.ID, lease.DeploymentID, lease.TenantID, lease.DepartmentID, lease.ApplicationID, lease.Units, lease.FencingToken, lease.Owner, lease.RequestID, lease.ExpiresAt, "active", now, now)
	if err != nil {
		return Lease{}, err
	}
	if err = tx.Commit(); err != nil {
		return Lease{}, err
	}
	return lease, nil
}

func (p *SQLProvider) ReleaseCapacity(ctx context.Context, lease Lease) error {
	if p == nil || p.db == nil {
		return ErrUnavailable
	}
	return p.releaseAt(ctx, lease, p.now().UTC())
}

func (p *SQLProvider) releaseAt(ctx context.Context, lease Lease, now time.Time) error {
	if p == nil || p.db == nil || lease.ID == "" || lease.DeploymentID == "" || lease.FencingToken <= 0 || !validScope(sharedkernel.Scope{TenantID: lease.TenantID, DepartmentID: lease.DepartmentID, ApplicationID: lease.ApplicationID}) {
		return ErrInvalid
	}
	var tenant, department, application string
	err := p.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id FROM platform_model_capacity_lease WHERE id=? AND deployment_id=? AND fencing_token=?`), lease.ID, lease.DeploymentID, lease.FencingToken).Scan(&tenant, &department, &application)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStaleLease
	}
	if err != nil {
		return err
	}
	if tenant != lease.TenantID || department != lease.DepartmentID || application != lease.ApplicationID {
		return ErrStaleLease
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var reserved int64
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT reserved_units FROM platform_model_capacity_pool WHERE deployment_id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), lease.DeploymentID, lease.TenantID, lease.DepartmentID, lease.ApplicationID).Scan(&reserved); err != nil {
		return err
	}
	var units int64
	var expiresAt time.Time
	var status string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT units,status,expires_at FROM platform_model_capacity_lease WHERE id=? AND deployment_id=? AND tenant_id=? AND department_id=? AND application_id=? AND fencing_token=? FOR UPDATE`), lease.ID, lease.DeploymentID, lease.TenantID, lease.DepartmentID, lease.ApplicationID, lease.FencingToken).Scan(&units, &status, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return ErrStaleLease
	} else if err != nil {
		return err
	}
	if status == "released" || status == "expired" {
		return tx.Commit()
	}
	if status != "active" || units <= 0 || reserved < units {
		return ErrStaleLease
	}
	leaseStatus := "released"
	if !expiresAt.After(now) {
		leaseStatus = "expired"
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_capacity_pool SET reserved_units=reserved_units-?,revision=revision+1,updated_at=? WHERE deployment_id=? AND reserved_units>=?`), units, now, lease.DeploymentID, units)
	if err != nil {
		return err
	}
	if err = affectedOne(result); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_capacity_lease SET status=?,updated_at=? WHERE id=? AND status='active' AND fencing_token=?`), leaseStatus, now, lease.ID, lease.FencingToken)
	if err != nil {
		return err
	}
	if err = affectedOne(result); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *SQLProvider) ReapExpired(ctx context.Context, before time.Time, limit int) (int, error) {
	if p == nil || p.db == nil {
		return 0, ErrUnavailable
	}
	if before.IsZero() {
		before = p.now().UTC()
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,deployment_id,tenant_id,department_id,application_id,units,fencing_token,owner,request_id,expires_at FROM platform_model_capacity_lease WHERE status='active' AND expires_at<=? ORDER BY expires_at,id LIMIT ?`), before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	leases := make([]Lease, 0, limit)
	for rows.Next() {
		var lease Lease
		if err = rows.Scan(&lease.ID, &lease.DeploymentID, &lease.TenantID, &lease.DepartmentID, &lease.ApplicationID, &lease.Units, &lease.FencingToken, &lease.Owner, &lease.RequestID, &lease.ExpiresAt); err != nil {
			rows.Close()
			return 0, err
		}
		leases = append(leases, lease)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	reaped := 0
	for _, lease := range leases {
		if err = p.releaseAt(ctx, lease, before.UTC()); err != nil {
			if errors.Is(err, ErrStaleLease) {
				continue
			}
			return reaped, err
		}
		reaped++
	}
	return reaped, nil
}

func reapDeploymentTx(ctx context.Context, tx *sql.Tx, deploymentID string, now time.Time, reserved *int64) error {
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,units,fencing_token FROM platform_model_capacity_lease WHERE deployment_id=? AND status='active' AND expires_at<=? ORDER BY expires_at,id LIMIT 100 FOR UPDATE`), deploymentID, now)
	if err != nil {
		return err
	}
	type expiredLease struct {
		id           string
		units, fence int64
	}
	expired := make([]expiredLease, 0)
	for rows.Next() {
		var lease expiredLease
		if err = rows.Scan(&lease.id, &lease.units, &lease.fence); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, lease)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, lease := range expired {
		if lease.units <= 0 || *reserved < lease.units {
			return errors.New("model capacity reservation counter underflow")
		}
		*reserved -= lease.units
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_capacity_lease SET status='expired',updated_at=? WHERE id=? AND status='active' AND fencing_token=?`), now, lease.id, lease.fence); err != nil {
			return err
		}
	}
	return nil
}

func validDeployment(d Deployment) bool {
	return d.ID != "" && validScope(sharedkernel.Scope{TenantID: d.TenantID, DepartmentID: d.DepartmentID, ApplicationID: d.ApplicationID}) && d.ModelVersionID != "" && d.CapacityUnits > 0
}

func validScope(scope sharedkernel.Scope) bool {
	return strings.TrimSpace(scope.TenantID) != "" && strings.TrimSpace(scope.DepartmentID) != "" && strings.TrimSpace(scope.ApplicationID) != ""
}

func validState(health, status string) bool {
	switch health {
	case "ready", "degraded":
		return status == "ready"
	case "unknown", "warming":
		return status == "pending"
	case "unavailable":
		return status == "failed"
	case "draining":
		return status == "draining"
	default:
		return false
	}
}

func accepting(health, status string) bool {
	return status == "ready" && (health == "ready" || health == "degraded")
}

func parseCapacityUnits(raw []byte) (int64, error) {
	var capacity struct {
		MaxConcurrentRequests int64 `json:"max_concurrent_requests"`
	}
	if err := json.Unmarshal(raw, &capacity); err != nil || capacity.MaxConcurrentRequests <= 0 || capacity.MaxConcurrentRequests > 1_000_000 {
		return 0, ErrInvalid
	}
	return capacity.MaxConcurrentRequests, nil
}

// ParseCapacityUnits validates the public Deployment capacity document.
func ParseCapacityUnits(raw []byte) (int64, error) { return parseCapacityUnits(raw) }

func affectedOne(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrStaleLease
	}
	return nil
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
