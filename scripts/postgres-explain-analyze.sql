-- Read-only diagnostics for platform-owned PostgreSQL tables.
-- Replace the trusted scope literals with an operator-approved scope.
-- EXPLAIN ANALYZE executes the SELECT; use the read-only transaction below.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT run_id,status,revision
FROM public.platform_execution_run
WHERE tenant_id='diagnostic-tenant'
  AND department_id='diagnostic-department'
  AND application_id='diagnostic-application'
  AND session_id='diagnostic-session'
ORDER BY run_id
LIMIT 20;
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT event_id,status,attempts,next_attempt_at
FROM public.platform_notification_outbox
WHERE next_attempt_at<=clock_timestamp()
  AND status IN ('pending','failed')
ORDER BY next_attempt_at,event_id
LIMIT 50;
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT generation_id,revision
FROM knowledge.active_generations
WHERE tenant_id='diagnostic-tenant'
  AND department_id='diagnostic-department'
  AND application_id='diagnostic-application'
  AND knowledge_id='diagnostic-knowledge';
ROLLBACK;
