# 平台版本化Schema迁移契约

## 第四十批Compose默认账户补充（最新）

后续session29625已针对含Close错误处理的当前源码完成真实MySQL/race复验，退出0；下文该项“尚未单独复验”为当时记录，现由此更新。业务E2E失败仍未解决。

平台Compose默认DB_DSN使用platform_runtime，仅DML；迁移DSN独立。migrate命令可在development模式显式引导固定开发账户，不覆盖已有密码/权限，冲突明确失败。密码仅24～128位URL-safe字符；生产必须设PLATFORM_DEV_RUNTIME_PASSWORD为空并自行配置独立账户，不允许开发引导。CREATE USER/GRANT非事务，失败可残留新账户，重试同凭据恢复，不能宣称原子回滚。根.env不修改；隔离验收栈生成随机运行密码。

真实SQL引导/重复/密码冲突/生产拒绝三轮race通过；随后连接Close错误处理尚未单独复验。正式当前源码Compose构建、迁移、DML平台及全部健康探测通过，但业务E2E失败，不等于整项目通过。真实失败为AUTHORIZATION_DENIED：旧夹具伪构造机器Scope却未创建真实IAM/Catalog授权（数据库授权0、安装0）。下一步修夹具受控授权，不得绕过运行期重验。MM-AUD-16及最终签核仍未关闭。

## 第三十九批生产装配补充（最新）

真实进程/十模块/迁移重放session71703三轮race PASS。生产main新增SHOW GRANTS核对：仅当前库DML及USAGE允许；DDL、全局DML、其他库、转授权、角色/表级及未知语法拒绝。不记录授权原文，迁移命令使用独立高权限账户、不适用此运行限制。session32977真实SQL证明DML允许及管理员拒绝，但真实主进程仍是development测试，生产主进程验证尚待。

生产K8s新增platform-schema-migrate Job，独立迁移Secret不注入运行Deployment，要求与平台同一镜像digest。apply门禁等待迁移Job成功后等待平台；运行进程若版本不符会拒绝启动，不能为等待迁移恢复自动DDL。新增网络策略仅允许数据库命名空间3306和DNS，外部数据库须运维overlay调整。Kustomize渲染/PowerShell语法/5项正式拓扑测试通过；未在生产集群执行。

Compose独立DML默认账户及当前源码栈验收仍待，MM-AUD-16不能关闭。pytest存在既有scope与cache权限警告，未掩盖。下文第三十七/三十八批是历史进展，三轮待执行项已经由本节更新。

## 第三十八批真实主进程补充

真实平台main二进制（race构建）已在Linux独立MySQL中，以仅SELECT/INSERT/UPDATE/DELETE用户启动并返回ready=200，发送中断后优雅退出；坏checksum或空版本明确非零退出。session42002通过。这只证明真实平台启动/拒绝路径，不替代三项目业务E2E。

首轮session90908发现policyasset/control_plane.go的Module.Start仍执行DDL；已移除并在迁移命令的DML模块用例中加入该模块，检查从九模块扩为十模块。此前下文九模块记录为第三十七批历史证据，不代表最新覆盖范围。当前三轮复验session71703尚在执行。

独立运行账户默认装配、生产权限强制检查、K8s迁移Job和当前源码Compose启动尚未完成，MM-AUD-16不能关闭。根.env及现有业务数据不变。

## 已实现

- 唯一迁移可执行文件为 `/app/migrate`（源码 `platform/cmd/migrate`）。迁移先连接数据库，不在连接阶段执行DDL；执行完整平台模块bundle后才写 `platform_schema_version`。
- 当前版本 `2026092801`，校验值由版本化模块清单计算。已发布版本不可原地修改，Schema变更必须增加版本。该校验值标识bundle清单，不宣称自动检测任意Go代码或实际DDL内容变化。
- MySQL数据库作用域GET_LOCK串行迁移；独立连接持有会话锁。释放锁失败显式返回错误。重复相同版本跳过，校验漂移或不兼容版本拒绝。没有未知版本自动降级/覆盖。
- MySQL DDL隐式提交，不能宣称DDL事务原子回滚。bundle中途失败不写完成版本；再次执行必须依靠各模块幂等Schema步骤恢复。失败状态不得通过版本检查。
- `schemaversion.Check` 仅执行SELECT；缺表、空版本、查询失败、不匹配版本或checksum均拒绝。正式真实MySQL测试证明只拥有SELECT/INSERT/UPDATE/DELETE的用户可读版本并写业务夹具，不能CREATE TABLE。
- 实际迁移命令的SQL测试新建独立库并执行两次，验证只有一个版本记录，执行/会话租约/工具/监管回执/通知表真实存在。没有触碰既有业务库。

## 尚未完成的装配条件

MM-AUD-16仍IN_PROGRESS。应用main已改ConnectSQLStore加版本Check；OpenSQLStore不再隐式迁移。九个模块Start不调用EnsureSchema/Migrate，测试仓储夹具通过仅_test.go的显式迁移初始化。迁移bundle已补齐模型容量与策略快照Resolver Schema（首版尚未部署，清单随修复补全后才冻结）。真实DML-only连接及九模块Start测试通过；还不能据此宣称整个平台进程及Worker/HTTP业务链路已完成最小权限验收。

Compose已装配platform-migrate一次性服务，平台依赖其成功完成；build/运行配置通过YAML anchor共享当前源码，迁移DSN使用独立PLATFORM_MIGRATION_DB_DSN。结构检查通过，未实际构建/启动本轮Compose。独立运行DML账户的默认装配与强制权限边界、K8s装配及真实进程最小权限启动还未验收。当前开发DSN仍可能使用root默认，不作为生产准出。根.env不改，生产密钥不复制到文档或镜像。

## 验证边界

`schema_test.go` 覆盖四个并发迁移者、失败重试、漂移/未来版本拒绝、DML-only用户；`cmd/migrate/main_test.go` 覆盖完整真实bundle和重放、模型容量/策略快照表、真实DML-only连接与九模块Start。Linux/MySQL三轮通过；全平台Go包race一次通过（真实预算SQL测试已启用）。真实DeepSeek、Python gRPC/TCP取消、Compose进程重启仍属显式跳过/专项E2E，不计PASS。这不是整个项目全量Docker E2E。

本地共享池是模块化单体的事务/迁移装配，不依赖进程内锁。后续多实例共享同一Schema版本检查，微服务拆分后各owner独立迁移并维护自己的版本，不共享私有表。
