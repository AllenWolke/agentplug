# SDK监督退出与平台持久交接

协议：`sdk-handler-exit/v1`。这是具体业务处理器退出后的交接收据，不是容器/进程停止证明，也不授予权限。

## 收据与信任边界

Execution v2等待响应可包含`handoff`，HTTP和gRPC使用同一十一字段结构：

| 字段 | 绑定事实 |
|---|---|
| version | 固定sdk-handler-exit/v1 |
| run_id | 原Run |
| execution_revision | 已退出的原执行代，1至2^53-1 |
| body_hash | 平台实际签发的完整命令正文摘要，不含Bearer |
| lease_token_hash | 原执行租约SHA256，不含租约原文 |
| input_fingerprint | SDK原业务输入、输入Schema及幂等键摘要 |
| origin_operation | 原invoke或run，恢复不改变原执行方式 |
| harness_key | 原暂停Harness状态键 |
| tool_name / call_id | 原待批准队首操作标识 |
| last_event_seq | 退出时实际waiting事件的序号，1至2^53-1 |

只有SDK监督层记录具体处理器实际退出、且本地状态仍为该执行代的Harness暂停，才生成收据。业务返回任意对象、普通waiting、accepted、网络超时、租约到期均不是证据。Python运输层先清除业务响应的handoff，再调用生命周期finalizer，并要求登记器已确认退出；Go/Java使用自身退出屏障。SDK的输入摘要用于同一已发布Agent版本恢复校验，不用于绕过平台原命令摘要或签名检查。

平台依赖已登记、受信任的Agent部署端点及SDK监督实现。摘要字段只是绑定事实，不是独立数字签名或操作系统死亡证据。若端点身份/传输无法确认、响应丢失或收据不匹配，应保留不确定执行边界并走既有controller停止证据，不得制造收据或仅依靠DB状态重启。上线时需一并核验部署来源、传输、SDK监督和签名恢复端点。

## 平台持久化与批准恢复

生产Dispatcher对照当前签发命令正文、Run执行修订及租约核验收据。SQLStore在原Run UPDATE和实际Session lease围栏内再次对照dispatch_command；与waiting状态、Outcome和waiting事件在同一事务保存。复用既有JSON事件/Outcome字段，无新增数据库表或暗式迁移。普通旧等待可以保存状态，但不自动产生交接证明。

`WaitingHandlerHandoffTx`只读取已提交等待收据，核验原等待修订、Outcome、原dispatch command及历史租约；不存在或不一致时拒绝。批准恢复CAS由存储层从此处读取收据，绑定当前批准的pending key/tool/call及检查点内容摘要，再持久化到非秘密resume引用，随后才清除旧租约。读取/保存收据不创建租约、不执行Agent、不释放预算。

每次派发前仍重新校验调用人与机器、当前安装/版本/策略/权限、祖先Run、原检查点head/revision/content hash和审批有效期。签名resume正文包含瞬时confirmation_token、原handoff及明确的checkpoint引用；Token不写入Run、Outbox、事件或日志。新的执行签名与租约属于新执行代，不能复用旧许可。相同已提交命令的浏览器回放只读，不生成新收据或重新派发。

## 当前阶段边界

本协议的接线、收据生产与三语言受控新进程引导已实现并完成必要编译/静态核对，尚未部署或通过真实跨进程场景验收。不可因MemoryRunStore重启变空就调用业务函数。

## 受控引导规则

恢复只能发生在已验签的resume入口，并在当前调用人/机器执行授权检查后进行。原收据run_id必须匹配当前Run，原执行修订严格小于当前签名修订、原租约摘要不同于新租约；原业务输入指纹必须等于SDK当前重新计算值。检查点引用仅接受namespace=harness、固定harness-loop/v1 Schema、原harness_key、1～64修订、64位小写内容Hash，execution_revision必须等于原收据修订。通过当前执行客户端读取公共State最新head，确认响应checkpoint非null以及上述实际字段逐项一致，并核对approval_required的FIFO队首工具/调用标识，再次检查当前执行授权；任何未知、权限失败、变更或冲突都拒绝，不能新建检查点、重新派发模型/工具或释放预算。

只允许SDK本地没有此Run执行代时从该已授权、已核验的原交接初始化生命周期投影。投影导入waiting、原Scope/幂等键以及实际last_event_seq，但不伪造过去的事件、输出或副作用。支持[执行世代事件区间](sdk-event-ranges.md)的Store随后在已验签新修订的区间内追加真实started事件，序号为max(新区间基数,原实际last_event_seq)+1；未实现该SPI的兼容Store沿原实际last_event_seq+1追加，不获得通用故障恢复的跨世代保证。自定义持久RunStore必须明确实现受控AdoptWaiting接口；不支持时拒绝，不能偷用StartRun当恢复。已有本地活跃代或无法确认退出的代不能被替换；已有本地安全暂停仍走原退出屏障。验签或读取检查点不得在全局生命周期锁内执行网络请求；最终注册时必须重查冲突。

MemoryRunStore新增投影导入并不使其成为独立的L2/L3权威存储。平台SQL Run/Outcome、公共State及签名交接继续拥有恢复事实；运行中崩溃且没有已提交收据时仍要求controller停止证据。事件序号能衔接，但旧SDK进程内事件正文不会被凭空恢复；历史平台事件继续从平台持久入口读取。

投影导入SPI只接受Scope、幂等键、事件基数及必要的非秘密暂停标识，不把完整ExecuteRequest、context_token或confirmation_token交给自定义Store。

## 已退出等待的取消

取消意图提交后，平台只读核验取消前一版waiting Outcome、实际签发dispatch修订/正文Hash和原租约绑定。没有原收据的旧waiting继续使用远端或controller停止确认。有效收据只证明对应暂停处理器退出；最终取消前仍检查供应商费用核账静默，再在原Run UPDATE/CAS事务重新核验同一收据，记录handler_exit_stop_confirmed与终态，清理原租约。不因SDK重启而要求旧内存状态存在，不重建运行或检查点。

正式平台worker把浏览器run意图重签为同步invoke，因此三示例通过同步返回交接收据。SDK原生异步run的202 ACK不携带收据，不能作为退出证明；本阶段未新增异步收据取回协议。
