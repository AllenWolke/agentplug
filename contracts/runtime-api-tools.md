# 受控只读API工具

平台启动层通过`PLATFORM_API_BINDINGS_FILE`读取不超过1MiB的严格JSON数组，使用受控HTTP客户端装配公共API工具。未配置时不开启。业务Agent仍通过SDK工具接口调用；注册配置不能由业务输入或模型修改。

每项必须包含`tool_name`（`api.`前缀）、固定`endpoint`、`tenant_id`、`application_id`、非空`agent_ids`、`read_only: true`、`timeout_seconds`（1～5）、`max_response_bytes`（1024～1048576）、`query_keys`与`input_schema`。可选`secret_ref`只能引用平台挂载凭证，不能在调用参数中选择。凭证所属上游账号必须只读；GET方法本身不能证明上游没有副作用，因此注册人必须核实服务契约及行级数据范围。

当前只支持GET和有界字符串查询字段。输入Schema及固定字段白名单双重校验；端点不得含内嵌凭证、query或fragment。生产使用HTTPS与受控端口，DNS/连接地址由现有防SSRF客户端检查，禁用代理和重定向；只有显式开发环境可用loopback。

该执行器复用工具网关的已发布策略、身份检查、执行租约、幂等账本和Observation，成功结果标记`execution_type: api`。输入不能提供URL、请求方法或任意Header。响应必须是单个JSON对象，保留大整数；错误响应正文不透传。只读失败可记录无业务写入副作用，但不能声称HTTP请求从未发出。不得将此语义应用于写操作或未经核实的GET服务。

本协议尚未覆盖写操作确认令牌、Code执行器、沙箱或完整Harness。正式业务IAM审批、版本发布和端到端验收仍待完成。
