FROM golang:1.25.1-bookworm AS build
ENV GOPROXY=https://goproxy.cn|https://mirrors.aliyun.com/goproxy/|https://proxy.golang.org,direct
WORKDIR /src
COPY workers/metric-runner/go.mod ./workers/metric-runner/
WORKDIR /src/workers/metric-runner
RUN go mod download
COPY workers/metric-runner/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/metric-runner ./cmd/runner
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/metric-service ./cmd/metric-service

# Bake a signed plugin registry into the image so the isolated dispatch service
# has a real, verifiable third-party plugin without any external volume. The
# registry tool generates a fresh Ed25519 keypair, pins the artifact digest in
# the descriptor, signs it and publishes the matching public.key next to the
# registry; the private key is never persisted. The declared and container
# resource bounds stay aligned (container limits must not exceed the registered
# envelope), which is what the runner re-verifies at plugin start-up.
# 把已签名的插件注册表烘焙进镜像，使隔离派发服务无需任何外部卷即拥有真实、可校验的第三方插件。
# 注册表工具生成全新 Ed25519 密钥对、把制品摘要固定进描述符、签名并把对应 public.key 发布在注册表
# 旁；私钥绝不落盘。声明的资源边界与容器边界保持一致（容器上限不得超过已登记信封），这正是 Runner
# 在插件启动期重新核对的内容。
FROM build AS registry
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/plugin-registry ./cmd/plugin-registry
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/example-plugin ./plugins/example
RUN mkdir -p /out/plugins
RUN printf '%s' '{"root":"/plugins","plugins":[{"id":"example_metric","version":"1.0.0","artifact":"/out/example-plugin","args":[],"limits":{"max_cpu_seconds":5,"max_memory_bytes":1073741824,"max_pids":128,"max_output_bytes":1048576,"timeout_seconds":30}}]}' > /out/registry.json
RUN /out/plugin-registry -root /plugins -spec /out/registry.json

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/metric-runner /metric-runner
COPY --from=build /out/metric-service /metric-service
COPY --from=registry /plugins /plugins
USER nonroot:nonroot
# The standalone runner image now serves the isolated dispatch face used by the
# Evaluation Worker; the sandbox trampoline re-executes this same binary.
# 独立 Runner 镜像现在提供评估 Worker 使用的隔离派发面；沙箱跳板会重新执行本二进制。
EXPOSE 8085
ENTRYPOINT ["/metric-service"]
