# 构建阶段
ARG GO_VERSION=1.23.5
FROM golang:${GO_VERSION}-alpine AS builder

# 安装构建依赖并清理缓存
RUN apk add --no-cache make git \
    && rm -rf /var/cache/apk/*

WORKDIR /proxypool-src
COPY . .
# 使用国内镜像加速依赖下载
ENV GOPROXY=https://goproxy.cn,direct
RUN make docker && mv bin/proxypool-docker /proxypool

# ----------------------------
# 运行阶段
FROM alpine:3.21

# 安装运行时依赖并清理缓存
RUN apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*

# 创建文件夹
RUN mkdir -p /app/config

WORKDIR /app

# 复制配置文件（显式创建目录）
COPY ./config/config.yaml ./config/source.yaml /app/config/
COPY --from=builder /proxypool /app/

# 设置时区
ENV TZ=Asia/Shanghai

# 暴露端口
EXPOSE 12580

# 健康检查（如果应用支持）
#HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:12580/health || exit 1

# 启动命令（使用 CMD 允许覆盖参数）
ENTRYPOINT ["/app/proxypool"]
CMD ["-d", "-c", "config/config.yaml"]

# 添加元数据标签（可选）
LABEL maintainer="proxypool@laibas.top" \
      description="ProxyPool Service"