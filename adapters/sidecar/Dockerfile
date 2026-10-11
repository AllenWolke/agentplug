# Build against the in-repo SDK the same way the reviewed legacy-http adapter
# image does, so the sidecar image builds from the repository root context.
# 与已评审的 legacy-http 适配器镜像相同方式基于仓库内 SDK 构建，
# 因此 sidecar 镜像以仓库根目录为构建上下文。
FROM golang:1.25 AS build
WORKDIR /src
COPY sdk/go /sdk/go
COPY adapters/sidecar/ ./
RUN go mod edit -replace github.com/lexagent/agent-platform-sdk-go=/sdk/go && CGO_ENABLED=0 go build -trimpath -o /out/sidecar-adapter ./cmd/adapter
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sidecar-adapter /sidecar-adapter
USER nonroot:nonroot
ENTRYPOINT ["/sidecar-adapter"]
