# Onboarding and delivery troubleshooting

[Developer path](README.md) · [简体中文](../zh/troubleshooting.md)

Check configuration → infrastructure → account scope → version/installation → policies → workload → user resources → business behavior. Granting everything is not diagnosis.

| Symptom | Check / next action |
| --- | --- |
| Preparation refuses | Existing `.env`/admin JSON; keep current credentials |
| Missing cryptography | Install the README prerequisite in the correct environment |
| Required Compose variables | Private env, independent gateway token, keys, database passwords; `config` validation |
| Console unreachable | Actual port/bind and service state; `status`/`smoke` |
| Schema mismatch | Matching migration, backup/history and DML runtime role |
| Bootstrap denied | Empty identity store, valid private shape/DSN/password or OIDC binding |
| Administrator lacks business entry | Separate execution authorization by another actor |
| Missing workspace | Company, membership and management scope; one-company rule |
| No agent | Published version and installation in current scope |
| Provisioning installation | Platform-reachable endpoint/image/probe and current revision observation |
| Execution denied | ID, issuer/audience/public key and signed v2 body |
| Resource denied | Caller/workload grants, bindings, current policies and denies |
| Model unavailable | Endpoint allowlist, Secret, approved model/price/access policy; legacy MODEL variables do not configure governance |
| Retrieval empty | Real source/index/version/embedding/scope and dual-identity ACLs |
| Preview stale | Reload revision/package/scope; preserve completed receipts |
| Mutation timeout | Query original receipt/batch; do not resend under a new key |
| K8s rejection | Complete approved overlay, real digests/Secrets/signatures; retain preflight |

Issues can include version, sanitized key names, steps, errors and request/run IDs. Never attach `.env`, cookies, tokens, database exports, private administrator JSON or confidential business contents. Use [private security reporting](../../../SECURITY.md).
