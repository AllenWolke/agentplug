// Package evaluationproduct manages tenant-scoped evaluation assets and
// release evidence for the modular Platform.
//
// HTTP contract (mount prefix: /api/modules/evaluation-product):
//   - GET /availability reports whether a product-contract Dispatcher was
//     injected; it does not infer compatibility from the legacy scalar Runner.
//   - GET/POST /datasets; GET /datasets/{id}; POST /datasets/{id}/review;
//     POST /datasets/{id}/publish
//   - GET/POST /metrics; GET /metrics/{id}; POST /metrics/{id}/publish
//   - GET/POST /suites; GET /suites/{id}
//   - GET/POST /runs; GET /runs/{id}; POST /runs/{id}/cancel
//     POST /runs/{id}/status (service identity only)
//   - GET /evidence; GET /evidence/{id}; POST /evidence/{runID}/publish
//     (service identity only)
//   - GET/POST /reviews; GET/POST /baselines; POST /gates/evaluate
//
// Every request authenticates the private gateway token and derives its
// tenant/department/application scope from trusted gateway headers. Browser
// requests additionally call the injected Identity Authorizer. Resource
// request bodies do not accept scope fields. Dataset and metric versions are
// immutable after publication; suite creation freezes a content hash snapshot;
// review and baseline mutations use separation of duties and revision CAS.
//
// POST /runs requires an injected durable Dispatcher. The built-in Runner
// supports a small deterministic metric set and delegates Agent invocation and
// artifact storage to scoped ports. Unsupported metrics fail closed rather
// than silently passing. With no Dispatcher, run creation fails with
// EVALUATOR_UNAVAILABLE. GET /availability reports only execution readiness;
// it is not a claim of model quality or trusted production evidence.
// evaluationproduct 管理模块化中台中的租户评测资产与发布证据。
package evaluationproduct
