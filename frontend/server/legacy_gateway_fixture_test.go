package main

var gatewayFixtureClaims = map[string]userClaims{
	"system.admin":   {"system.admin", "系统管理员", "tenant-demo", "dept-tech", "科技运维部", "app-platform-ops", []string{"admin", "auditor"}, 0, ""},
	"platform.admin": {"platform.admin", "平台管理员", "tenant-demo", "dept-platform", "智能体平台部", "app-platform-admin", []string{"platform_admin", "auditor"}, 0, ""},
	"fixture.admin":  {"fixture.admin", "合规应用管理员", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"department_admin", "application_admin", "release_admin", "prompt_admin", "tool_admin", "operator", "reviewer", "auditor"}, 0, ""},
	"fixture.user":   {"fixture.user", "合规业务用户", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"operator", "reviewer"}, 0, ""},
	// Least-privilege demo actors are separate so browser E2E exercises the
	// same requester/reviewer/operator/verifier separation enforced by SQL.
	// 最小权限演示身份彼此独立，使浏览器 E2E 覆盖数据库强制执行的岗位分离。
	"fixture.requester": {"fixture.requester", "业务发起用户", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"operator"}, 0, ""},
	"fixture.reviewer":  {"fixture.reviewer", "业务审核用户", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"reviewer"}, 0, ""},
	"fixture.operator":  {"fixture.operator", "业务执行用户", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"operator"}, 0, ""},
	"fixture.verifier":  {"fixture.verifier", "业务复核用户", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"reviewer"}, 0, ""},
	"integration.admin": {"integration.admin", "集成接入管理员", "tenant-demo", "dept-demo", "示例业务部", "app-demo", []string{"application_admin", "auditor"}, 0, ""},
}

func init() { demoClaims = gatewayFixtureClaims }
