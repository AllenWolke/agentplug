# 执行进程退出后的受控恢复

SDK正常取消必须等待实际业务处理器退出。若进程崩溃、旧SDK没有退出记录或机器丢失，平台不能凭租约过期、HTTP超时或RunStore终态判定旧执行已经停止。运行保持`cancelling`或`recovering`，会话顺序和租约继续占用。

平台提供`StopEvidenceVerifier`公共端口，让可信部署控制器证明旧进程已经退出。默认不启用该替代停止证据来源；正常SDK签名停止确认继续可用。验证停止凭据后仍要通过公共模型账本协调检查，不能把未知供应商费用当作已结算。

## 取消与模型用量

公共模型能力在发送前保存请求恢复意图和预算预留。发送前已观察到调用人取消时，不再向供应商发送请求，并按未发送证据释放预算。已进入发送阶段的请求按原持久化截止时间有界收取供应商回执，不因浏览器断开或SDK线程中断丢弃已产生的真实用量。取消后的调用人不能取得模型答案，后续公共能力调用仍需通过实时授权。

平台将已知回执写入账本并协调结算，不重新调用模型。收取回执的窗口仍受原截止时间限制；进程崩溃、网络故障或供应商超时导致费用未知时，保留待人工协调状态和预算，不能将其推断为免费。SDK确认退出与模型账本完成协调均满足后，平台才释放该会话租约。运维日志只记录固定停止阶段与允许的错误码，不记录签名密钥、Token、请求或答案正文。

## 本机文件验证器

部署控制器维护专用目录及独立32字节随机密钥，将其只读挂载到平台。配置如下，值是容器内路径：

```dotenv
PLATFORM_EXECUTION_STOP_RECEIPT_DIR=/run/secrets/controller-stop-receipts
PLATFORM_EXECUTION_STOP_RECEIPT_KEY_FILE=/run/secrets/controller-stop-receipts/controller.key
```

密钥仅属于部署控制器和平台。业务Agent、普通用户、权限管理员和浏览器都不获得该密钥或目录写权限。文件验证器信任持钥控制器的进程退出证明；它不自行读取Docker socket，签名也不替代控制器对运行环境的实际检查。生产应通过已有可信部署控制器实现该端口，并保护控制器密钥和审计记录。

控制器从平台冻结待停止运行的ID、原执行版本（意图CAS版本减1）、租约SHA-256、原始持久化请求字节SHA-256、执行endpoint、创建时间、停止意图时间和审批镜像摘要。完整请求摘要包含调用人、安装实例、Agent版本、会话、运行和策略等原始命令内容。平台另核对持久化请求与当前可信作用域一致性。快照由部署管理员取得，不能直接采用业务用户提交的字段。

仓库的`record_runtime_container_stop.py`用于本机Docker部署。它只允许原项目或`agentplug-test-*`专用测试项目，默认只验证；带`--execute`才实际停止。验证完整容器ID、Compose项目/服务、网络别名、已审批镜像和启动世代，禁用重启并停止该容器；再次检查PID=0、状态exited、未重启以及退出时间晚于停止意图，才签发凭据。

```powershell
python -B scripts/record_runtime_container_stop.py `
  --snapshot .local-secrets/controller/pending-run-snapshot.json `
  --container-id <完整64位容器ID> `
  --key-file .local-secrets/controller/controller.key `
  --receipt-dir .local-secrets/controller/receipts `
  --execute
```

快照字段为`run_id`、`execution_revision`、`lease_token_hash`、`request_hash`、`endpoint`、`created_at`、`intent_at`、`image_digest`、`compose_project`和`compose_service`。路径和ID须由部署管理员填写；命令不包含密钥内容、密码或Token。脚本不连接或改写平台数据库，已存在凭据不覆盖。

凭据文件名为运行ID的SHA-256加`.json`，内容包含原始JSON载荷的Base64和HMAC-SHA-256签名。平台验证大小/格式/签名、运行与执行版本/租约/请求/endpoint、实际进程标识及时间约束；错误凭据失败闭合，缺少凭据时走正常SDK停止路径。模型账本完成协调后，在CAS事务内同时记录`runtime_process_stop_confirmed`事件与取消/恢复变化。取消不返回业务输出；恢复保留原请求，不直接重跑业务图。

完整ID绑定某个原进程；原进程停止确认和平台事务完成之后，才恢复部署服务或发布新版本。重启后的SDK本身不能声称已观察到上一进程的处理器退出。部署控制器应保留停止凭据及镜像/进程核对记录，禁止用普通用户填写的“已停止”声明或直接修改运行状态替代恢复流程。
