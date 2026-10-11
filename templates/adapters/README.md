# Adapter templates

Each adapter kind is generated as an isolated, platform-governed workload. The
legacy Agent source remains untouched; descriptors and mappings are immutable
inputs to the adapter runtime.

Per kind, `agentctl generate-adapter` renders these assets instead of emitting
one shared blob, so `legacy-http`, `grpc`, `process` and `sidecar` ship
genuinely different deployment contracts:

| Asset | Purpose |
|---|---|
| `manifest.json` | Adapter manifest; `{{ .AgentID }}` is substituted at generation time. |
| `mapping.json` | Declarative mapping input (the generator emits the platform `agent-mapping/v1` form). |
| `profile.json` | Kind profile: `isolation`, `transport`, `port`, declared and unsupported capabilities, schemas. |
| `deploy/deployment.yaml` | K8s Deployment expressing the kind's isolation (sandbox rlimits/cgroup for `process`, read-only mTLS for `sidecar`). |
| `deploy/networkpolicy.yaml` | Default-deny K8s NetworkPolicy; inbound execution traffic is limited to `platform-app`, while adapter egress follows only the declared upstream policy. |

`profile.json` is cross-checked against the generator's `runtimeFor(kind)`
contract: an asset that declares a different isolation fails generation closed
rather than silently shipping a mismatched deployment. The generator also emits
`schema.json`, `capabilities.json` (declared vs. unsupported capability gaps) and
`fixtures/lifecycle.json` from the same profile.
