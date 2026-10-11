package agenteval

type Definition struct{ ID, Dimension, Name, Description, Unit, Direction string }

// Definitions is the screenshot's complete nine-dimensional metric registry.
func Definitions() []Definition {
	var out []Definition
	rate := func(dim string, pairs ...string) {
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, Definition{pairs[i], dim, pairs[i+1], "通过该项明确断言的适用机会 / 已取得证据的适用机会；缺失另列，不计为通过", "ratio", "higher_is_better"})
		}
	}
	bad := func(dim string, pairs ...string) {
		n := len(out)
		rate(dim, pairs...)
		for i := n; i < len(out); i++ {
			out[i].Direction = "lower_is_better"
			out[i].Description = "发生该问题的适用机会 / 已取得证据的适用机会；缺失另列"
		}
	}
	rate("task", "task_success", "Task Success Rate", "domain_correctness", "Domain Correctness", "complete", "Complete Rate", "human_acceptance", "Human Acceptance Rate", "first_pass_success", "First-pass Success Rate")
	rate("tool", "tool_call_accuracy", "Tool Call Accuracy", "tool_parameter_accuracy", "Tool Parameter Accuracy", "tool_call_success", "Tool Call Success Rate")
	bad("tool", "wrong_tool", "Wrong Tool Rate", "unnecessary_tool", "Unnecessary Tool Call Rate", "missing_tool", "Missing Tool Call Rate")
	rate("planning", "plan_correctness", "Plan Correctness", "step_efficiency", "Step Efficiency", "replan_success", "Replan Success Rate", "early_stop_accuracy", "Early Stop Accuracy")
	rate("context", "context_precision", "Context Precision", "context_recall", "Context Recall", "groundedness", "Groundedness", "faithfulness", "Faithfulness", "citation_accuracy", "Citation Accuracy", "prompt_injection_resistance", "Prompt Injection Resistance")
	rate("state_memory", "state_consistency", "State Consistency", "checkpoint_resume_success", "Checkpoint Resume Success Rate", "memory_precision", "Memory Precision")
	bad("state_memory", "duplicate_action", "Duplicate Action Rate", "memory_pollution", "Memory Pollution Rate")
	bad("safety", "permission_violation", "Permission Violation Rate", "sensitive_data_leakage", "Sensitive Data Leakage Rate", "unsafe_tool_call", "Unsafe Tool Call Rate", "prompt_injection_attack_success", "Prompt Injection Attack Success Rate", "unauthorized_data_access", "Unauthorized Data Access Rate")
	rate("reliability", "failure_recovery", "Failure Recovery Rate", "retry_success", "Retry Success Rate", "timeout_handling", "Timeout Handling Rate", "resume_success", "Resume Success Rate", "handoff", "Handoff Rate", "dlq", "DLQ Rate", "unknown_side_effect_handling", "UNKNOWN Side-effect Safe Handling")
	out[len(out)-3].Direction = "policy_dependent"
	out[len(out)-3].Description = "进入Handoff的适用机会比例，需结合人工接管策略评价"
	out[len(out)-2].Direction = "policy_dependent"
	out[len(out)-2].Description = "进入DLQ的适用机会比例，需结合故障处置策略评价"
	rate("cost_latency", "cache_hit", "Cache Hit Rate")
	for _, r := range []Definition{
		{"average_latency", "cost_latency", "Average Latency", "完成任务的实际运行延迟均值", "ms", "lower_is_better"},
		{"p95_latency", "cost_latency", "P95 Latency", "nearest-rank P95；至少20个样本", "ms", "lower_is_better"},
		{"p99_latency", "cost_latency", "P99 Latency", "nearest-rank P99；至少100个样本", "ms", "lower_is_better"},
		{"ttft", "cost_latency", "TTFT", "实际首token到达时间；不得用首事件或总延迟替代", "ms", "lower_is_better"},
		{"token_cost", "cost_latency", "Token Cost per Task", "已确认input/output token之和的任务均值", "tokens", "lower_is_better"},
		{"model_cost", "cost_latency", "Model Cost per Task", "已确认模型费用任务均值，币种遵循平台账本", "cost_micros", "lower_is_better"},
		{"tool_cost", "cost_latency", "Tool Cost per Task", "已确认工具计价任务均值；未定价不记零", "cost_micros", "lower_is_better"},
		{"model_calls", "cost_latency", "Model Calls per Task", "已确认模型调用任务均值", "calls", "lower_is_better"},
		{"loop_count", "planning", "Loop Count", "实际Harness循环次数均值", "rounds", "lower_is_better"},
	} {
		out = append(out, r)
	}
	rate("observability", "trace_completeness", "Trace Completeness")
	return out
}
