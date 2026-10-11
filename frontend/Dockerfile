FROM node:22-bookworm-slim AS web-build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund --fetch-retries=5 --fetch-retry-mintimeout=10000 --fetch-retry-maxtimeout=120000
COPY frontend/index.html frontend/vite.config.js frontend/styles.css ./
COPY frontend/src ./src
RUN npm run build

FROM golang:1.25.1-bookworm AS gateway-build
WORKDIR /src/frontend
COPY frontend/go.mod ./go.mod
COPY frontend/server ./server
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/frontend-gateway ./server

FROM alpine:3.21
RUN addgroup -S lexagent && adduser -S -G lexagent lexagent
WORKDIR /app
COPY --from=gateway-build /out/frontend-gateway /usr/local/bin/frontend-gateway
COPY --from=web-build /src/frontend/dist ./
USER lexagent
EXPOSE 80
# Modular-monolith default: the presentation gateway talks to the single
# platform process.  Legacy deployments must override this explicitly in
# their own historical Compose fixture; new images never default to them.
# 模块化单体默认值：展示网关只连接唯一平台进程；旧部署若仍需运行历史夹具，
# 必须在历史 Compose 中显式覆盖，新镜像不再默认连接旧 Backend。
ENV LISTEN_ADDR=:80 PLATFORM_URL=http://platform-app:8080 DEPLOYMENT_PROFILE=modular-compose COOKIE_SECURE=false
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD wget -qO- http://localhost/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/frontend-gateway"]
