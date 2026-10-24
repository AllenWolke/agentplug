# syntax=docker/dockerfile:1
# Build the modular-monolith platform from the repository root.
# 从仓库根目录构建模块化单体平台，保证 Docker/Linux 与本地模块布局一致。
FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS build

WORKDIR /src/platform
# Use the official module proxy by default. Private/offline environments can
# override this build arg with their approved internal mirror.
# 默认使用官方模块代理；私有化或离线环境通过 build-arg 指向受控内部镜像。
ARG GOPROXY=https://proxy.golang.org,direct
ARG TARGETOS=linux
ARG TARGETARCH
ENV GOPROXY=${GOPROXY}
COPY platform/go.mod ./go.mod
COPY platform/ ./
COPY contracts/code-runtime/ /src/contracts/code-runtime/
COPY contracts/agent-evaluation/go/ /src/contracts/agent-evaluation/go/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    downloaded=false; \
    for attempt in 1 2 3 4 5; do \
        if go mod download; then downloaded=true; break; fi; \
        echo "Go module download attempt ${attempt} failed; retrying" >&2; \
        sleep 3; \
    done; \
    test "$downloaded" = true; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/platform ./cmd/platform; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/bootstrap-admin ./cmd/bootstrap-admin; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/deployment-observe ./cmd/deployment-observe; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/migrate-legacy-auth ./cmd/migrate-legacy-auth; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/migrate-permissions ./cmd/migrate-permissions; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/identity-inspect ./cmd/identity-inspect; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/publish-policies ./cmd/publish-policies; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/configure-workloads ./cmd/configure-workloads

FROM alpine:3.21

RUN apk upgrade --no-cache && apk add --no-cache ca-certificates wget \
    && addgroup -g 10001 -S lexagent \
    && adduser -u 10001 -S -G lexagent lexagent

WORKDIR /app
COPY --from=build /out/platform /app/platform
COPY --from=build /out/migrate /app/migrate
COPY --from=build /out/bootstrap-admin /app/bootstrap-admin
COPY --from=build /out/deployment-observe /app/deployment-observe
COPY --from=build /out/migrate-legacy-auth /app/migrate-legacy-auth
COPY --from=build /out/migrate-permissions /app/migrate-permissions
COPY --from=build /out/identity-inspect /app/identity-inspect
COPY --from=build /out/publish-policies /app/publish-policies
COPY --from=build /out/configure-workloads /app/configure-workloads

RUN chown 10001:10001 /app/platform /app/migrate /app/bootstrap-admin /app/deployment-observe /app/migrate-legacy-auth /app/migrate-permissions /app/identity-inspect /app/publish-policies /app/configure-workloads
USER 10001:10001

EXPOSE 8080 8081
ENTRYPOINT ["/app/platform"]
