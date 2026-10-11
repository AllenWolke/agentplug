# Spring AI domain extension point / Spring AI 领域扩展点

Domain nodes receive the verified request and its per-execution SDK capability
client. Reuse the platform Model/Tool/Knowledge/Memory gateways; do not construct
a provider with `OPENAI_API_KEY`. Configured direct clients are rejected when
the governed client is absent. Deterministic echo is a transport fixture only.
/ 领域节点接收已验证请求与逐运行 SDK 客户端。模型、工具、检索、记忆走平台网关，
不得自行装配厂商凭据。缺少受控客户端时禁止直连，回显仅为传输一致性夹具。
