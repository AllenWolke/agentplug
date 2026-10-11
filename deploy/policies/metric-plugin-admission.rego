package lexagent.metric

default allow = false

# Admission for a third-party metric plugin. Every clause maps to a bound the
# metric runner independently re-verifies in-process, so this policy is the
# cluster-side half of the same contract rather than a second, softer one.
# 第三方指标插件的准入。每条都与指标 Runner 在进程内独立复核的上限一一对应，因此本策略是同一
# 契约的集群侧一半，而不是另一套更宽松的规则。
allow {
  input.signature_verified == true
  startswith(input.artifact_digest, "sha256:")
  input.network == "none"
  input.user == "nonroot"
  input.timeout_seconds > 0
  input.timeout_seconds <= 60
  input.output_bytes > 0
  input.output_bytes <= 1048576
  input.max_pids > 0
  input.max_pids <= 128
  input.memory_bytes > 0
  input.memory_bytes <= 268435456
}
