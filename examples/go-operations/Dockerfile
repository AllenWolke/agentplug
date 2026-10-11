# Build from the repository root so the example consumes the actual Go SDK.
FROM golang:1.25-bookworm AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /workspace
COPY sdk/go/ sdk/go/
COPY examples/go-operations/ examples/go-operations/
WORKDIR /workspace/examples/go-operations
RUN CGO_ENABLED=0 go build -trimpath -o /agent .

FROM scratch
COPY --from=build /agent /agent
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/agent"]
