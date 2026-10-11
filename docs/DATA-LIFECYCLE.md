# 数据生命周期与删除边界

适用于当前模块化平台和独立业务 Agent、Docker 和 Linux 原生部署。保留天数、Legal Hold 责任人与归档位置由部署者确定；下表描述实现行为，不承诺全系统物理擦除或法定保留合规。

## 持久化资产与实际行为

| 数据 | 位置 / 实现 | 保留与删除行为 |
|---|---|---|
| 会话、消息与修订、分享、导出和删除申请 | 平台 PostgreSQL `platform_conversation_*`；[实现](../platform/internal/conversation/sql_store.go) | 审批删除和到期扫描先标为 deleted、禁止继续。新的 v2 审批同事务建立擦除任务：至少等待 24 小时，满足当前权限、保全、保留及运行静止条件后，内部 Worker 删除消息、修订、分享、导出行，清除标题/预览和申请原因；保留归属墓碑、审批/任务/回执。旧审批与到期扫描不自动补建擦除任务 |
| 保留策略与 Legal Hold | 同库 retention policy / legal hold 表 | 治理身份按租户/部门/应用及 qa/check 设置策略、扫描或保全。扫描显式触发且有界，没有默认定时清理。先提交的有效 Hold 阻止审批删除/到期处置。已进入 v2 擦除队列且尚未完成的会话允许新增 Hold，阻止实际载荷擦除；已擦除或没有擦除任务的 deleted 会话拒绝新增 Hold |
| Agent Checkpoint | CHECKPOINT_DSN 的 checkpoint/blob/write 表；[Provider](../sdk/python/agent_platform_sdk/checkpoint.py) | 保存恢复状态，没有接入会话删除的自动清理器。活动/可恢复 Run 的检查点不得擅自清理 |
| 短期 Memory | platform_memory_entry；[实现](../platform/internal/capability/memory_sql.go) | 到期不可读，读取时或同作用域写入时清理到期行；不是全表定时 TTL。冷作用域过期字节可能保留；旧读取不得清理已并发刷新的有效行 |
| Run、事件、结果、幂等/租约、调用与账本 | execution/capability/usagecost SQL 表 | 不自动年龄删除；保留恢复、重试去重、外部副作用与计费事实。不能删掉事实后继续接受同一幂等键 |
| 审计、通知 Outbox/DLQ、身份和 Grant | audit/notification/identity 等 SQL 表 | 撤权/停用和通知状态改变不是擦除；没有自动 WORM 归档或全表统一年龄清理器 |
| 评测资产、版本、Run 和输出载荷 | evaluation/policy/model 等 SQL 表 | 保存执行来源与质量事实；不随会话删除。输出业务内容需另行访问/保留审查 |
| 公共知识源、文档版本与向量索引 | 平台 PostgreSQL source/head/version/event 表；配置的 PostgreSQL + pgvector `knowledge.*` 投影；实现见 `platform/internal/knowledge/source.go` 和 `platform/internal/knowledge/schema.sql` | 文档更新、ACL 变化和删除写入带修订的源版本/事件；删除版本正文为空，历史版本与事件没有自动年龄清理。pgvector generation/chunks 是投影，检索会核对当前 source/ACL facts，陈旧投影不能授权返回内容。生产检索 Provider 需要配置 `KNOWLEDGE_DATABASE_DSN`；源库与投影分库时，投影同步及备份/恢复顺序由部署方协调，不承诺跨库原子性或历史正文物理擦除 |
| 下载副本、日志/Trace、SQL 备份 | 下载者、监控与备份存储 | 不随会话同步删除；分别配置访问、脱敏、轮转、到期与保全豁免 |

按目标部署配置盘点实际数据库、对象存储、运行与副本映射。未配置保留策略时，会话不会自行到期删除。

## 治理操作

conversation 模块提供 `/retention-policy`（GET/PUT）、`POST /retention-policy?op=sweep`、`/legal-holds` 及释放保全入口，详见[HTTP 模块](../platform/internal/conversation/module.go)。这些是模块相对路由，需经过认证、作用域映射和治理授权；不得公开内部端口或直接信任客户端 Scope。

策略支持 qa/check、1–36500 天及 enabled；扫描按会话更新时间计算到期，以 before/limit 有界处理。先在隔离库验证策略，使用当前时间扫描并核对 scanned/held/disposed。释放保全是独立授权操作，不应自动释放以使清理通过。

会话导出需要申请与授权批准，在同一 PostgreSQL 一致性快照中导出会话摘要和全部当前消息，包含消息元数据，按时间与 ID 排序；不导出修订历史、其他模块或外部系统数据。完整 JSON 上限为 8 MiB，超限明确返回 HTTP 413 / EXPORT_TOO_LARGE，且不保存部分导出。下载者负责副本访问和到期删除；会话删除后原导出入口不能继续提供其内容。该入口不是跨系统个人数据导出或全资产归档工具。

## 物理清理与归档

会话载荷 Worker 使用数据库租约、单调版本和超时接管；检查不可变审批记录、原审批人当前权限、申请人与审批人不同，以及法律保全、配置的保留期和执行运行事实。正文删除、回执及审计/Outbox 同事务提交；失败回滚正文，15 分钟后重试，最多 10 次后转 failed。回执摘要证明该会话载荷事务的结果，不代表磁盘不可恢复擦除或外部副本删除。运行事实、账本、已下载副本、Checkpoint、RAG、审计和备份不在本次载荷擦除范围。

PLATFORM_CONVERSATION_ERASURE_ENABLED 默认 true；恢复期间设为 false，先叠加备份后已提交的撤权、Hold 与删除事实并对账，再恢复 Worker。运行期不执行 DDL，新表/执行索引由版本 2026100501 的部署迁移安装；不会为历史删除记录推断或补造审批人。

目前没有统一全资产物理擦除 API，或跨 RAG、Checkpoint、审计和备份的原子删除任务。若生产业务要求这些能力，需要专项实现；仅有 deleted 状态或隐藏前端记录不能证明物理擦除完成。

不要直接对全部表执行年龄删除。先冻结身份/会话/Run/Checkpoint/外部文档映射与有效 Hold 清单，核对活动 Run、重试窗口、账本、审计和外部副作用；由所有人批准保留事实及可擦除载荷的范围。保存受控归档清单与摘要，在隔离副本验证清理、恢复和重复请求行为后，才执行经审核的目标环境操作。使用独立账户、最小权限和操作审计；仓库不提供可直接对未知生产库运行的全表清理脚本。

## 恢复后对账

旧备份可能恢复出删除前内容或释放前 Hold。恢复期间保持业务入口、任务领取与通知发送关闭，取得备份时点之后的受控删除、保全与撤权记录，按资产映射补做对账；验证会话/下载入口、授权、Checkpoint、公共知识投影 与副本。确认恢复不会再次产生外部副作用后再开放服务。备份工具验证 SQL 完整性与表集合，不自动完成业务对账。

备份到期删除及 Hold 豁免由存储策略实施；离线加密副本、异地副本、日志归档与已下载文件也须纳入清单。真实治理记录不得放入公开 GitHub 仓库。
