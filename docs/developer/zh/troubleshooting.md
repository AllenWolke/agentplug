# 入门与交付排障

[入门路线](README.md) · [English](../en/troubleshooting.md)

按“配置 → 基础服务 → 账号范围 → 版本 / 安装 → 策略 → 机器 → 用户资源 → 业务运行”检查。每一步修复后核验具体结果，不把增加全部权限作为排障动作。

| 现象 | 优先检查 | 下一步 |
| --- | --- | --- |
| 准备命令拒绝 | `.env` 或一次性管理员 JSON 已存在 | 使用原文件；不要重生成数据库和签名凭据 |
| Python 找不到 cryptography | 准备脚本前置依赖 | 在相应 Python / 虚拟环境安装 README 中的依赖 |
| Compose 提示必填值 | 是否使用生成的私有 `.env`；网关 Token、公钥和数据库密码 | `compose.py config`，按[配置分层](configuration.md)核对，不公开原值 |
| 地址无法访问 | `FRONTEND_HOST_PORT` 与绑定；Docker / 进程是否就绪 | `status`、`smoke`；本地源码默认端口与 Compose 不同 |
| Schema 不匹配 | 当前版本对应的迁移是否成功 | 先备份，使用匹配版本迁移；不删历史、不让运行账号获得 DDL |
| 首位管理员初始化拒绝 | 是否已经有身份数据；JSON 形状、DML DSN、密码 / OIDC 绑定 | 已有库用正常管理路径；不覆盖已有管理员 |
| 管理员没有业务入口 | 管理身份与 Agent 运行权不同 | 查看管理范围；由其他获准操作者赋予需要的业务使用权 |
| 工作空间选项不足 | 账号公司、部门成员、管理 scope 与授权目标 | 用户属于一个公司，不能通过切换前端跨公司扩大范围 |
| 目录中没有助手 | 是否发布版本并在当前范围创建安装 | 按[交付](delivery.md)核对 Definition / Version / Installation |
| 安装一直 provisioning | 平台网络能否到真实端点，实际镜像 / 探针是否匹配 | 部署控制器观测当前 desired revision；不手改数据库为 active |
| Agent 就绪但执行拒绝 | ID、issuer、audience、公钥、签名正文是否对应 | 不跳过 SDK 的校验；浏览器提交业务输入，由平台签名 |
| 资源拒绝 | 用户 / 机器分别授权、当前策略、绑定、版本、deny | 读取权限解释和审计；用当前使用包重新预览 |
| 模型不可用 | 端点 allowlist、Secret、批准 ModelVersion / PriceVersion / Access Policy | 历史 MODEL_PROVIDER / MODEL_API_KEY 不配置当前治理模型 |
| 知识无结果 | 实际源与索引、版本、Embedding、Scope、双主体 ACL | 使用已有绑定真实文档，查看检索证据和引用 |
| 批量预览过期 | revision、package digest 或管理范围变化 | 读取最新事实，重新预览；保留已成功项和原批次 receipt |
| 写请求超时 | 服务器是否已经提交 | 查原 batch / receipt；不要重新生成 key 重发 |
| K8s 预检拒绝 | 原始模板仍有占位值、缺 digest / Secret / 签名清单 | 配置批准覆盖层；不删门禁，不把 base 当完整生产部署 |

Issue 中可附源码版本、去敏配置键名、具体步骤、错误代码、request / run ID 和去敏日志。不要附 `.env`、Cookie、Bearer Token、数据库导出、真实业务内容或一次性管理员 JSON。安全问题使用 [SECURITY.md](../../../SECURITY.md)。
