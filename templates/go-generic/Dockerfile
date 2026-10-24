FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
COPY platform_entry ./platform_entry
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/agent ./platform_entry
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent /agent
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/agent"]
