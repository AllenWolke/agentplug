FROM golang:1.25.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY platform_entry ./platform_entry
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/agent ./platform_entry
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent /agent
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/agent"]
