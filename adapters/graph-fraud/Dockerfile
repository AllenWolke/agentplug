# GraphFraud is deployed as an external, zero-intrusion legacy HTTP Agent.
# GraphFraud 以外置、零侵入的存量 HTTP Agent 方式部署。
#
# Build from the repository root so the adapter and the language-neutral SDK
# are compiled together:
#   docker build -f adapters/graph-fraud/Dockerfile .
# 需从仓库根目录构建，使 Adapter 与语言无关 SDK 一起编译。
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY sdk/go /src/sdk/go
COPY adapters/legacy-http /src/adapters/legacy-http
WORKDIR /src/adapters/legacy-http
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/graph-fraud-adapter ./cmd/adapter

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/graph-fraud-adapter /graph-fraud-adapter

# The upstream URL and platform public key are runtime secrets/configuration;
# they are intentionally not baked into this image.
# 上游地址和平台公钥属于运行时配置/Secret，刻意不写入镜像。
ENV AGENT_ID=graph-fraud-assistant \
    LEGACY_INVOKE_PATH=/api/chat

EXPOSE 8080
ENTRYPOINT ["/graph-fraud-adapter"]
