# syntax=docker/dockerfile:1
FROM golang:1.25.1-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src/cli/agent-eval
COPY cli/agent-eval/ ./
COPY contracts/agent-evaluation/go/ /src/contracts/agent-evaluation/go/
COPY sdk/go/ /src/sdk/go/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/agent-eval ./cmd/agent-eval
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/agent-eval /agent-eval
USER 10001:10001
WORKDIR /reports
ENTRYPOINT ["/agent-eval"]
