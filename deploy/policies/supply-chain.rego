package lexagent.supplychain

default allow := false

# Production artifacts require digest pinning and all three attestations.
# 生产制品必须固定 digest，并具有 SBOM、签名和来源证明。
allow if {
  startswith(input.image, "sha256:")
  input.sbom_verified
  input.signature_verified
  input.provenance_verified
  input.critical_vulnerabilities == 0
}
