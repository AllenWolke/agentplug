# 使用业务 Agent 开发与交付 skill

[入门路线](README.md) · [English](../en/skill.md)

仓库中的 [`agentplug-business-agent`](../../../skills/agentplug-business-agent/SKILL.md) 是提供给代码助手的可复用说明。它指导开发、审查、测试和一站式接入，并复用现有 SDK、部署入口和治理 API。它不是绕过平台权限的新服务，也不意味着加载后就自动取得生产变更权限。

## 安装或直接使用

在 AgentPlug 仓库根目录，可将 skill 复制到自己的 Codex 技能目录。下面命令同时适用 PowerShell 与通常的 shell；目标已存在时拒绝覆盖：

```text
python -c "import os,shutil; from pathlib import Path; root=Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex'))); shutil.copytree('skills/agentplug-business-agent',root/'skills/agentplug-business-agent')"
```

让客户端重新加载技能后调用 `$agentplug-business-agent`。支持读取 `SKILL.md` 的其他助手也可以直接读仓库文件，无需改变全局环境。skill 先定位真实平台源码和业务工程，安装路径不被当成仓库根目录。

## 示例请求

**开发与审查，不部署：**

```text
使用 $agentplug-business-agent，在当前 AgentPlug 仓库基础上开发一个工单助手。
业务工程放在我指定的目录。先复用平台模型、知识与工具能力，检查功能完整性，
执行本地业务和协议测试，给出交付计划；这一阶段只开发和审查。
```

**对已有 Agent 一站式交付：**

```text
使用 $agentplug-business-agent，检查我现有的业务 Agent 是否充分复用平台公共能力。
目标平台、公司、部门、业务工程路径和用户名单以我提供的真实信息为准。
准备可审查的镜像、版本、策略、部署和绑定计划，列出实际影响，
在我的授权范围内完成部署、部门 Agent 开通和指定用户批量授权，
使用指定普通用户验证真实运行，同时验证未授权和跨公司用户被拒绝。
输出不含密码的登录验收清单和证据，缺失环境不得写成通过。
```

提供平台地址和部署方式、Agent 路径 / 名称 / 版本、公司 / 部门、预期用户、使用操作及期限。凭据由私有配置和相应认证工具提供，不把 `.env`、Cookie 或模型 Key 贴进聊天。

## 输出和边界

skill 输出业务需求与公共组件映射、功能遗漏、测试结果、具体部署与权限计划，以及实际 run / receipt / batch 等验收事实。对不用的能力说明不适用，不以模型调用数量衡量复用。

部署按本地 / Compose / K8s 的真实边界执行。三个固定示例脚本不能直接套用于任意业务。版本审批、独立发布者、工作负载认证、部门使用上限、用户使用包和再次认证继续生效；响应未知时查原收据，不盲目重发。

最终区分“代码检查通过”“服务就绪”“安装 active”“指定用户真实运行通过”。只有完成后两项及所需策略 / 授权验证，才能报告 Agent 已在平台供这些用户使用。
