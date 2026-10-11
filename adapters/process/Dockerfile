# The process adapter's job is to exec the pre-registered legacy agent process
# inside its own container, so the runtime image must be able to host arbitrary
# operator-registered binaries (shell/coreutils included); distroless cannot.
# The numeric non-root UID keeps the restricted Pod Security profile.
# process 适配器的职责是在自身容器内 exec 预注册的存量 Agent 进程，因此运行时
# 镜像必须能承载运维注册的任意二进制（含 shell/coreutils）；distroless 做不到。
# 数字非 root UID 保持满足 restricted Pod Security。
FROM golang:1.25 AS build
WORKDIR /src
COPY sdk/go /sdk/go
COPY adapters/process/ ./
RUN go mod edit -replace github.com/lexagent/agent-platform-sdk-go=/sdk/go && CGO_ENABLED=0 go build -trimpath -o /out/process-adapter ./cmd/adapter
FROM debian:12-slim
COPY --from=build /out/process-adapter /process-adapter
USER 65532:65532
ENTRYPOINT ["/process-adapter"]
