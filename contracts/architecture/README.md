# 模块边界与动态 SQL 登记

此目录是受审阅的架构契约，不是从当前实现自动生成的通过基线。

- `table-owners.json`：显式表→模块所有者；实际访问模块由 `platform/internal/<module>/` 的文件路径计算。未知表、外模块读写与 JOIN 均拒绝。模块内多个 Repository 可访问自身表；不能以表名前缀推测 owner。
- `dynamic-sql.json`：无法完全静态解析的 SQL，按文件及接收者/函数登记。每项必须有完整文件 SHA-256、所属表清单和具体审阅原因。源码变化即失效，不能通过刷新摘要自动放行。
- 允许的登记仅涉及本文件的固定 WHERE 条件、参数化输入和源码内枚举迁移列。审阅必须包含 SQL 构造 helper；helper 若搬到其他文件，应先扩展依赖摘要验证或消除动态构造，不得沿用只有调用文件摘要的登记。
- 审阅表清单不是任意 SQL 输入的授权：请求参数只能绑定为值，不得成为表名、列名或 SQL 片段。新增任意动态来源先拒绝，完成实现与负向测试后才可登记。
- PostgreSQL `pg_trigger` 不作为业务表所有权登记。仅 `execution.EnsureGenerationJournalSchema` 中四个固定、只读触发器存在性查询可读取该系统目录；其精确迁移语句受专用 AST/SQL 例外约束，不能读取任意触发器记录，也不能写系统目录。迁移创建触发器只作用于 execution 自有 generation journal 表。
- `information_schema.tables/columns/statistics` 仅允许读取；业务表不存在共享读写豁免。跨模块应调用显式 Port；组合根负责注入实现，业务 Repository 不构造其他模块的 SQL 实现。

门禁：

```powershell
python scripts/verify_modular_boundaries.py
python -m pytest -q -p no:cacheprovider tests/release-validation/modular_table_boundary_test.py
cd platform
go test ./internal/architecture -count=1
```

Go 门禁使用 AST 解析导入、别名、公共符号、SQL 调用参数、常量拼接、同包常量和有限赋值分支；非静态表达式必须登记。Python 门禁承担文件→模块、表所有权、多实际 writer、静态 SQL 和 Agent 禁止持有 DB 的检查。两者缺一不可，不以单独一个脚本 PASS 宣称架构完成。

已覆盖的反例包括双 writer、别名和平铺实现导入、未知表、跨模块 JOIN/拼接、分支中的外模块表、未登记动态 SQL、登记后源码漂移、动态登记外模块/未知表、注释文案与不可读编码。真实数据库事务与 Docker 功能验收另行执行，静态边界通过不代表生产准出。
