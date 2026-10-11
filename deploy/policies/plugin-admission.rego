package lexagent.plugin.admission

default allow := false

# Built-in trusted plugins may run in process; every other plugin is isolated.
# 内置可信插件可进程内运行；其他插件必须进程外隔离。
allow if {
  input.signature_verified
  startswith(input.artifact_digest, "sha256:")
  input.isolation_level in {"sidecar", "container", "sandbox"}
}

allow if {
  input.signature_verified
  startswith(input.artifact_digest, "sha256:")
  input.isolation_level == "in_process"
  input.built_in_trusted
}
