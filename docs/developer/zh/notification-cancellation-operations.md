# Kafka 通知与取消补偿的启用和历史保护

Kafka 通知使用 `PLATFORM_EVENT_BUS_MODE=kafka`（进程内为 `EVENT_BUS_MODE`）。可撤回的本人通知和取消补偿使用 `PLATFORM_CANCELLATION_COMPENSATION_ENABLED=true`。两者缺省仍沿用原部署行为，启用不会自动把历史失败通知恢复为待发送，也不会证明历史未知模型费用已结清。

## 启用条件

先验证本项目的通知、补偿 Schema 标记和校验和，以及 Code Runtime 的停止证明校验配置；迁移使用显式维护入口，运行账户仍只持有 DML 权限。确认没有正在运行、等待审批或发送结果未确认的新工作，再备份当前数据库、有效配置和运行镜像。数据库备份须在本项目独立、无外部网络的数据库恢复并验证。

暂停本项目平台写入后，记录三个来源主题 `platform.audit`、`platform.notification`、`agent-platform.identity.v1` 的所有分区末尾位置。建立本项目全新的消费组，将该组提交位置初始化为这些末尾位置，核对当前位置、末尾位置一致且无活跃成员；不重置任何原消费组。显式创建本项目 DLQ 主题。完成下面的持久保护清单后才启动消费者与补偿工作器。

## 持久保护清单

容器变量 `PLATFORM_AUTOMATIC_RECOVERY_HOLD_FILE` 指向只读目录 `/run/secrets/runtime-control/` 内的文件。宿主目录由 `PLATFORM_RUNTIME_CONTROL_DIR` 指定。清单格式如下，示例中的运行标识、消费组和偏移必须替换为实际盘点结果：

```json
{
  "version": "automatic-recovery-holds/v1",
  "run_ids": ["historical-run-needing-operator-review"],
  "tool_scope_hashes": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
  "kafka_group_id": "agentplug-notifications-reviewed-cutover",
  "kafka_start_offsets": [
    {"topic": "platform.audit", "partition": 0, "offset": 100},
    {"topic": "platform.notification", "partition": 0, "offset": 10},
    {"topic": "agent-platform.identity.v1", "partition": 0, "offset": 0}
  ]
}
```

`run_ids` 应包含历史取消中任务、费用未知任务的根运行和历史补偿根任务。执行恢复在读取具体任务和调用模型对账、停止控制之前跳过这些标识；补偿队列在更新领取时间之前过滤它们。因此旧记录不被改写，也不会挤占新任务的分页和队列容量。直接进入自动确认、补偿领取或补偿完成路径同样受保护。

`tool_scope_hashes` 是历史未知工具账本的原作用域哈希，可选且必须为小写 64 位十六进制。它在工具恢复 SQL 分页之前过滤，并阻止直接恢复和退避更新，连无法解码旧回执查询的记录也能保留。不得从当前请求推测或重写原作用域。模型费用为 `manual` 的记录继续使用已有的人工核对隔离规则。

分区偏移为允许消费的第一条记录位置。更早的消息在解码、投递尝试记账和 DLQ 写入之前被跳过，只有确认提交成功才读取下一条。持久边界与消费组绑定；启动时消费组不符或偏移超出订阅主题会失败。消费组位置丢失后，仍保留这份清单，不能仅依赖 Kafka 已提交位置防止历史重放。

将清单原始字节的 SHA-256 写入 `PLATFORM_AUTOMATIC_RECOVERY_HOLD_SHA256`，保持文件只读。文件与 SHA 必须一起配置；格式、版本、重复标识、非法偏移或 SHA 不符会阻止启动。清单只在启动时读取，业务请求不能更改。零配置时保留原行为。上限为 100,000 个运行标识、4,096 个分区边界和 8 MiB 文件。

历史保护不会自动到期。只有取得原供应商收据、可信停止证明和预算证据并逐项审核后，才可另行计划释放指定任务；本次启用不执行这一动作。不要清空清单、移动消费起点到更早位置、恢复历史 Outbox 状态或用零费用替代未知费用。

## 验证和回退

三个示例需分别验证实际通知 Outbox 发布、投递成功和本人收件箱送达；其他用户读取应被拒绝。审批通过与续接使用原任务和原检查点，平台重启后仍须可用。沙箱核对标准输出 `4`、退出码和容器删除收据；固定协作核对子任务版本和终态。取消后核对停止证明、补偿完成、预算关闭和终态幂等；已送达通知撤回时保留原文与撤回收据。

启用后再次比较历史任务、模型、通知、DLQ、补偿及授权行的摘要，验证旧未知记录没有变化。新消费组的主题末尾位置会继续前进，不代表允许修改部署时保存的最低偏移。

本次启用不新增数据库迁移。需要关闭新功能时，优先保持当前平台镜像和历史保护清单，仅把 `PLATFORM_EVENT_BUS_MODE` 设为 `disabled`、`PLATFORM_CANCELLATION_COMPENSATION_ENABLED` 设为 `false`，再重建本项目平台容器。不要恢复整个旧环境文件而丢失清单配置；旧镜像缺少本轮保护，仍会恢复原有工具轮询行为，不能作为保留冻结边界的一键回退。

回退前确认没有新任务正在执行，另存当前数据和配置；保留启用期间产生的通知、补偿及模型收据，不还原旧数据库覆盖新结果。启用前镜像和配置已备份，可用于独立端口与独立恢复数据库的回退验证；切回更早镜像前必须先解决其历史保护兼容性。Schema 不兼容的版本仍按[完整升级回退流程](public-capabilities-upgrade.md#迁移部署与回退)处理。不能删除本项目卷、重建账号或操作对照项目。
