ARG CODE_RUNTIME_DOCKER_CLI_IMAGE

FROM golang:1.25.1-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY contracts/code-runtime/ ./contracts/code-runtime/
COPY workers/code-runtime/go.mod ./workers/code-runtime/go.mod
COPY workers/code-runtime/ ./workers/code-runtime/
WORKDIR /src/workers/code-runtime
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/code-runtime ./cmd/code-runtime

FROM ${CODE_RUNTIME_DOCKER_CLI_IMAGE} AS runtime
USER 0:0
RUN mkdir -p /etc/agentplug-code /var/lib/agentplug-code/receipts /var/lib/agentplug-code/docker \
    && chown -R 10001:10001 /etc/agentplug-code /var/lib/agentplug-code \
    && chmod 0750 /etc/agentplug-code \
    && chmod 0700 /var/lib/agentplug-code /var/lib/agentplug-code/receipts /var/lib/agentplug-code/docker \
    && command -v docker >/dev/null
COPY --from=build --chown=10001:10001 /out/code-runtime /usr/local/bin/code-runtime
ENV CODE_RUNTIME_CONFIG_FILE=/etc/agentplug-code/code-runtime.json
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/code-runtime"]
