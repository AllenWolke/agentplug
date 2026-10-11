# Go / Eino Agent Execution v2 示例

该服务是可运行的语言无关 v2 HTTP Agent：Manifest 与 `invoke`、`run`、`resume`、`cancel`、`events`
均使用 `sdk/go` 契约。请求在调用 Eino 图之前必须通过 Ed25519 平台上下文能力校验；不得把租户、用户或
运行 ID 当作可直接信任的客户端参数。

```bash
AGENT_PLATFORM_PUBLIC_KEY_BASE64="<gateway-ed25519-raw-public-key>" go run .
python conformance/runner/run.py --base-url http://127.0.0.1:8080 \
  --lifecycle-fixture /path/to/gateway-signed-lifecycle.json
```

示例的 `runs` 仅用于演示生命周期，生产 Agent 必须将状态、幂等键和事件放入按 `ScopeKey` 隔离的
共享存储，因此其 HTTP 契约无需随单体拆分或多副本部署而变化。
