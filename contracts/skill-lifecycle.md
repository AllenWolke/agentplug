# 公共Skill生命周期与渐进披露

状态：生命周期核心、PostgreSQL存储、显式迁移、三SDK加载接口、IAM/租约/审计、人工控制面与界面、资源目录以及三语言Harness渐进加载源码已开发。平台模型边界依赖校验已开发；协议边界值统一、实际授权/示例整合、部署与整体场景验收待完成。此文定义公共协议，不代表已上线。

Skill是版本化的非可信业务指令资料，机器执行始终经过平台模型、工具、知识、Runtime及预算边界。依赖声明只限制现有能力，不授予权限。

`skill-bundle/v1`包括skill_id、version_id、title、summary、sections、required_tools、required_knowledge。摘要最多2048字节，章节最多16个、每章16KiB，总JSON最多64KiB；依赖列表有界且无重复。排序归一化依赖列表后生成SHA-256摘要，持久正文不可改写，同版本不同摘要冲突。

注册后为submitted，由另一有权人按准确摘要和CAS版本审核为approved或rejected。revoked不可重新发布、加载或因回滚复活。每次注册、审核、撤销及发布均要求当前权限，并与元数据审计/Outbox处于同一事务。

Release指定stable_version、可选candidate_version、candidate_basis_points（1～10000）及CAS revision；零灰度时不配置candidate。所有目标必须已批准、人员分离通过且当前允许发布。回滚以新Release revision选择旧的已批准版本，保持历史正文和发布历史不可变。

运行第一次加载确定性选择稳定或灰度版本，以完整调用人/Agent安装版本/Run/Session作用域固定Pin。后续发布或回滚影响新运行，已有运行保持Pin。每次摘要或章节披露重新检查当前双身份权限、版本未撤销及依赖能力交集；Pin不缓存授权。

`skill-disclosure/v1`先返回title/summary/section_names及版本、摘要、Release revision；显式请求section才返回该章正文，避免一次性加载全部内容。结果标注`instruction_trust=untrusted_data`。

SQL适配拥有版本、Release、发布历史与运行Pin四张表。事务应用命名空间锁保护首次创建与CAS，加载时锁定对应版本，提交前重复当前授权检查；实际authorizer须检查执行连续性并锁定权限版本。元数据Audit使用既有事务Recorder，Outbox原子性由该Recorder装配保障。缺授权或审计依赖时拒绝事务，披露失败不返回正文。

Schema只供显式迁移调用；当前未迁移正式数据库。源码和编译证据不能替代真实权限、SQL故障回滚、灰度/回滚/撤权与三语言业务验收。

显式迁移版本为2026100403，保留0402校验并支持符合原校验的升级。业务入口`POST /internal/skill/load`接收`{"skill_id":"example.skill","section":""}`先披露摘要；再指定section获取单章。身份及作用域由平台签名上下文提供，不能在输入中覆写。SDK：Go `LoadSkill(ctx,id,section)`、Python `load_skill(id,section)`、Java `loadSkill(id,section)`。控制面生命周期接口后续单独接入，Agent不能以加载接口办理审核或发布。

Runtime策略allowed_skills显式允许Skill ID；空值不开放。加载使用已验签执行上下文、当前租约及双身份资源权限，依赖工具/知识与发布策略求交。Pin不缓存授权。

人工接口`/api/modules/skills/{inspect,register,review,publish}`均为POST，可附`namespace:{tenant_id,department_id,application_id}`。当前主体与会话由浏览器网关派生，namespace只选择同租户的已存在有效目标应用，不能覆写主体；管理权限按目标应用复查。省略namespace时使用当前工作空间。注册/撤销需policy.manage，审核/发布需release.approve，查询可由任一权限办理，作者禁止自审。

授权动作`skill.load`和新角色`skill_user/v1`已加入目录，不改写旧角色版本。业务用户须显式获得对应安装的角色绑定和Skill Grant，Agent机器身份须有同一安装的Skill Grant；还须在已发布Runtime策略allowed_skills中配置Skill ID。资源校验验证已发布安装、当前策略允许，并通过Skill元数据Port确认至少一个当前Release目标仍已批准。只验证资源存在不授予权限。权限管理员需在明确委托包含skill_user及skill.load时办理，不能因新增动作自动扩大原委托。

Harness模型编排字段skill_bindings为{skill_id:{version_id,digest}}，最多四项，由披露结果生成，不传递给模型供应商。生成、实际发送、模型结果及只读回执检查已有Run Pin、批准状态、当前Runtime allowed_skills、双身份及声明的工具/知识依赖。该字段绑定幂等指纹，缺省时保持旧指纹。模型入口不会创建Skill Pin；须先经正常加载授权。授权失效不抹除已产生费用，阻止结果披露。跨撤权时序与恢复的实际整体验收仍待统一部署后完成。

Skill选择编排输入skill_requests可省略或为空数组，明确null拒绝；每项仅skill_id/sections，sections可省略或为空数组，null拒绝。最多四个不同Skill、各四个不同章节。标识符长度1～128 UTF-8字节且须有效Unicode，不含边界Unicode White_Space、星号或NUL/CR/LF。平台披露摘要须64位小写十六进制。三语言源码按此规则处理；场景一致性及跨语言检查点摘要仍待总体验收。示例Skill资料位于examples/{go-operations,python-documents,java-tickets}/skills/guidance.v1.json，尚未注册、审核、发布或授权。

公共知识答案入口支持skill_requests加skill_bindings，须先通过正常摘要加载取得既有Run Pin。服务端再加载摘要/明确章节，聚合16KiB，作为非可信数据供引用生成使用。答案缓存键绑定披露内容；命中、模型生成和最终返回仍复查依赖。Python SDK load_skill_bindings和answer_knowledge关键字参数复用此路径，不额外调用模型。当前为未部署源码，实际缓存/撤权/SQL组合待整体场景验收。
