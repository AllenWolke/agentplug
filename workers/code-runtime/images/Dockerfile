# Build one of the python/javascript/shell targets, then pin its actual image ID.
# The public project owns these images; upstream language images are base layers.
FROM golang:1.25.1-bookworm AS guard-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY contracts/code-runtime/ ./contracts/code-runtime/
COPY workers/code-runtime/ ./workers/code-runtime/
WORKDIR /src/workers/code-runtime
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/code-sandbox-guard ./cmd/code-sandbox-guard

FROM python:3.12-alpine AS python
COPY --from=guard-build /out/code-sandbox-guard /usr/local/bin/code-sandbox-guard
LABEL io.agentplug.code.filesystem-guard="landlock-v3" io.agentplug.code.language="python"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/code-sandbox-guard", "python"]

FROM node:22-bookworm-slim AS javascript
COPY --from=guard-build /out/code-sandbox-guard /usr/local/bin/code-sandbox-guard
LABEL io.agentplug.code.filesystem-guard="landlock-v3" io.agentplug.code.language="javascript"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/code-sandbox-guard", "javascript"]

FROM alpine:3.21 AS shell
COPY --from=guard-build /out/code-sandbox-guard /usr/local/bin/code-sandbox-guard
LABEL io.agentplug.code.filesystem-guard="landlock-v3" io.agentplug.code.language="shell"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/code-sandbox-guard", "shell"]
