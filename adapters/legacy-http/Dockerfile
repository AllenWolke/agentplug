FROM golang:1.25 AS build
WORKDIR /src
COPY sdk/go /sdk/go
COPY adapters/legacy-http/ ./
RUN go mod edit -replace github.com/lexagent/agent-platform-sdk-go=/sdk/go && CGO_ENABLED=0 go build -trimpath -o /out/adapter ./cmd/adapter
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/adapter /adapter
EXPOSE 8080
ENTRYPOINT ["/adapter"]
