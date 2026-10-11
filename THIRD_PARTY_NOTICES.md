# Third-party dependencies

AgentPlug's project code is distributed under the root [MIT license](LICENSE).
Third-party libraries, runtimes, tools, images and external services retain their
own licenses and notices. The project's MIT license does not replace them.

The source repository does not distribute downloaded Maven JARs, installed
Node/Python packages, Go module caches or container images. Build tools resolve
dependencies from the checked-in manifests and lock/checksum files:

| Component | Dependency records |
|---|---|
| Go platform, frontend gateway, SDK, adapters, CLI and Runner | Each module's `go.mod` and `go.sum` |
| Python SDK and framework templates | SDK and template `pyproject.toml` / `requirements.txt` |
| Java SDK and examples/templates | Each Maven module's `pom.xml` |
| React frontend | Frontend's `package.json` and `package-lock.json` |
| Container runtimes and external software | Dockerfiles and Compose/Kustomize image declarations |

When distributing built binaries, containers or offline dependency bundles,
retain the third-party license and copyright notices required by the resolved
dependencies. Source-release checks must not be used to approve a separately
assembled binary bundle. The supply-chain workflow produces image SBOMs; use
the actual artifact's SBOM and upstream license files for that artifact's review.

This inventory describes dependency sources and distribution boundaries. It is
not a claim that every dependency uses MIT or that an external service grants
redistribution rights under this project's license.
