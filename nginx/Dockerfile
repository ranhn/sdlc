FROM nginx:1.25-alpine

# 复制自定义配置
COPY nginx.conf /etc/nginx/nginx.conf

# 复制前端构建产物（由 docker-compose 挂载覆盖，这里放默认值）
COPY frontend/dist /usr/share/nginx/html

# 创建 SSL 证书目录
RUN mkdir -p /etc/nginx/ssl /var/www/certbot

# 暴露端口
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]