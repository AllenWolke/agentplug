# Sidecar Adapter

Sidecar Adapter 用于隔离运行「平台无法内联执行、但需要受治理出站」的存量 Agent。它强制 `SIDECAR_UPSTREAM_URL` 为已登记 `https://` 地址，校验签名执行能力后**只转发该能力**，绝不转发调用方身份头。

## 双向 TLS（mTLS）

Sidecar 必须出示自身工作负载身份，**不是**单向 HTTPS 调用：

| 变量 | 含义 |
|---|---|
| `SIDECAR_MTLS_CERT_FILE` / `SIDECAR_MTLS_KEY_FILE` | 必填；客户端证书与私钥，用于向已登记上游证明自身身份 |
| `SIDECAR_MTLS_CA_FILE` | 可选；固定上游信任锚（未提供时使用系统信任库） |

- 缺少客户端证书或私钥时**启动即失败闭合**（`sidecar mutual TLS is required`），不会退化成未认证的 TLS。
- 服务端证书校验**永不关闭**（没有 `InsecureSkipVerify`），并强制 `TLS >= 1.2`。
- 上游 3xx 一律不跟随，避免被攻陷的上游把平台已校验的出站流量引到未通过地址策略的主机。

## 能力声明

Sidecar **只宣告自己真正提供的能力**：

- `invoke` / `health`：始终提供。
- `events`：仅当登记 `SIDECAR_EVENTS_PATH` 时宣告，并以 `GET <upstream><events_path>` + `Accept: text/event-stream` 订阅、**逐帧透传并 flush**，支持 `Last-Event-ID` 恢复。
- `cancel` / `resume` / `checkpoint`：契约已定义但本 Adapter **未实现**，统一返回 `501` 与平台稳定错误码 `UNSUPPORTED_CAPABILITY`（`{"error":{"code","message","retryable"}}`），使平台能把「未实现」与传输故障区分开，永不伪装成已支持。
