# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS web-builder
WORKDIR /src/web
ARG NPM_REGISTRY=https://mirrors.cloud.tencent.com/npm/
COPY web/package.json web/package-lock.json ./
RUN npm ci --registry=${NPM_REGISTRY} --no-audit --no-fund
COPY . /src
WORKDIR /src/web
RUN npm run build

FROM golang:1.23-bookworm AS go-builder
WORKDIR /src
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /src/web/dist ./web/dist
RUN go build -trimpath -ldflags="-s -w" -o /out/chinese-can-fly .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fly && useradd --system --gid fly --home-dir /nonexistent --shell /usr/sbin/nologin fly \
    && install -d -o fly -g fly -m 0750 /var/lib/chinese-can-fly
COPY --from=go-builder /out/chinese-can-fly /usr/local/bin/chinese-can-fly
USER fly
EXPOSE 8080
VOLUME ["/var/lib/chinese-can-fly"]
ENTRYPOINT ["/usr/local/bin/chinese-can-fly"]
