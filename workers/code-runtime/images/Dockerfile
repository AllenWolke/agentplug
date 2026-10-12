# Build one of the python/javascript/shell targets, then pin its actual image ID.
# The public project owns these images; upstream language images are base layers.
FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm AS guard-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY contracts/code-runtime/ ./contracts/code-runtime/
COPY workers/code-runtime/ ./workers/code-runtime/
WORKDIR /src/workers/code-runtime
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/code-sandbox-guard ./cmd/code-sandbox-guard

FROM python:3.12-alpine AS python
RUN apk upgrade --no-cache
COPY --from=guard-build /out/code-sandbox-guard /usr/local/bin/code-sandbox-guard
LABEL io.agentplug.code.filesystem-guard="landlock-v3" io.agentplug.code.language="python"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/code-sandbox-guard", "python"]

FROM node:22-bookworm-slim AS javascript
# The sandbox executes Node.js directly. Dependency installers are build tools.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg
COPY --from=guard-build /out/code-sandbox-guard /usr/local/bin/code-sandbox-guard
LABEL io.agentplug.code.filesystem-guard="landlock-v3" io.agentplug.code.language="javascript"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/code-sandbox-guard", "javascript"]

FROM alpine:3.21 AS shell
RUN apk upgrade --no-cache
COPY --from=guard-build /out/code-sandbox-guard /usr/local/bin/code-sandbox-guard
LABEL io.agentplug.code.filesystem-guard="landlock-v3" io.agentplug.code.language="shell"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/code-sandbox-guard", "shell"]
