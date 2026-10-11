# 固定外部出站覆盖层

本覆盖层基于外部 PostgreSQL 示例，为平台的模型/遥测网关和 OIDC 代理的 IdP 网关增加 TCP/443 出站。业务 Agent 不直接连接模型厂商，只调用平台公共能力。

替换全部 `REPLACE_WITH_*` CIDR 为经批准的固定端点或网关。发布预检拒绝缺失目标、未限定 HTTPS、无效 CIDR，以及 IPv4 大于 /24 或 IPv6 大于 /64 的宽泛网络。每个新增目标都需要独立批准和目标 CNI 实测。

前端的 OIDC 再次认证会访问 IdP 的 Discovery、Token 和 JWKS 端点，必须配置本覆盖层的前端 TCP/443 定向出站。预检要求同时保留平台 TCP/8080、认证代理 TCP/4180 和 kube-system DNS；不接受缺少 IdP HTTPS、宽泛目标或额外端口的前端策略。

标准 Kubernetes NetworkPolicy 不按域名实施控制。动态地址使用固定网关，或为批准的 FQDN-aware CNI 扩展发布准入与正反例验证。该示例不是生产批准；完整流程见[生产发布说明](../../production/README.md)。
