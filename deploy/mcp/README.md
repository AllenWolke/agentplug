# 平台公共MCP工具装配

该目录提供配置格式示例，默认不启用MCP。`bindings.example.json`中的域名及Schema仅为占位，不能直接作为真实服务配置。

运维在私有目录创建`bindings.json`，填写已批准的HTTPS服务端点、远端工具名、平台工具名和实际输入Schema。Schema必须与发现结果完全一致，变化时平台拒绝调用；服务端的只读/破坏性注释不会扩大权限。

风险等级由本机运维配置`risk`（`read_only`、`write`、`high`）；省略时按`write`处理。只有核实服务契约和凭据只读权限后才可选择`read_only`。只读工具`timeout_seconds`范围1～3秒，写操作及高风险工具1～5秒；发布策略只能进一步收紧。写操作必须携带显式`call_id`和操作绑定批准令牌，不能用模型给出的布尔值确认。远端工具注释不能降低本机风险等级。

在私有`.env`中设置`PLATFORM_MCP_BINDINGS_DIR`为该目录，以及`PLATFORM_MCP_BINDINGS_FILE=/etc/platform/mcp/bindings.json`。Compose只读挂载配置。凭据正文单独保存于平台已挂载的`PLATFORM_MODEL_SECRET_DIR`，配置仅使用`secret://mcp/documents.key`等相对引用；业务Agent不挂载此凭据。

平台公开工具策略仍需正常注册审批发布，将`mcp.documents.search`加入`allowed_tools`，并按调用人和Agent机器身份分别办理工具资源Grant。Function Calling的`functions`定义绑定模型函数名和该工具名；业务Agent通过仓库SDK调用平台，不连接MCP端点。敏感工具保持平台审批要求，模型建议不能代替确认。

平台使用官方MCP Go SDK的Streamable HTTP客户端；关闭自动重试、客户端roots、sampling、elicitation及自动多轮回调。发现最多4页、每页128个工具；输入Schema最大16KiB、结果最大1MiB；发现和调用共同受上述本机风险分类截止时间限制。发现及Schema失败发生在工具提交前；工具调用后的响应丢失保留未知回执，不视为无副作用。现有平台工具SQL账本负责幂等、取消、权限及租约检查。

业务Agent的三语言调用方式见[SDK开发指南](../../docs/开发者指南/三语言SDK业务Agent开发指南.md)。
