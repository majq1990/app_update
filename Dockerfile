
# 使用一个包含 Python 和 Debian Buster 的轻量级基础镜像
FROM python:3.9-slim-buster

# 设置工作目录
WORKDIR /app

# 修复 Debian Buster 仓库问题：将源指向阿里云镜像服务器的归档路径
# 这是因为 Debian Buster (OldStable) 的主仓库可能已迁移到归档
# 替换为阿里云的 Debian Buster 镜像源，使用 /debian-archive/ 路径
RUN echo "deb http://mirrors.aliyun.com/debian-archive/debian/ buster main non-free contrib" > /etc/apt/sources.list && \
    echo "deb-src http://mirrors.aliyun.com/debian-archive/debian/ buster main non-free contrib" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-archive/debian-security buster/updates main" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.aliyun.com/debian-archive/debian-security buster/updates main" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-archive/debian/ buster-updates main non-free contrib" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.aliyun.com/debian-archive/debian/ buster-updates main non-free contrib" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-archive/debian/ buster-backports main non-free contrib" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.aliyun.com/debian-archive/debian/ buster-backports main non-free contrib" >> /etc/apt/sources.list

# 安装必要的系统依赖：
# openssh-client 用于 SSH 连接
# sshpass 用于非交互式 SSH 密码传递 (注意：生产环境推荐使用SSH密钥)
# rsync 用于文件同步
# dos2unix 用于处理Windows换行符问题
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    rsync \
    dos2unix && \
    rm -rf /var/lib/apt/lists/*

# 复制 Python 依赖文件
COPY requirements.txt .
# 安装 Python 依赖（PyYAML 用于处理 YAML 配置文件，requests 用于HTTP请求）
RUN pip install --no-cache-dir -r requirements.txt

# 复制整个应用更新工具目录到容器中
# 假设 Dockerfile 位于 app_updater 目录的同级
COPY app_updater /app/app_updater

# 设置 app_updater 目录为工作目录，方便直接运行脚本
WORKDIR /app/app_updater

# 确保 app_manager.sh 脚本是可执行的，并处理可能的DOS行尾符
RUN dos2unix app_manager.sh && chmod +x app_manager.sh

# 定义容器启动时执行的命令
# ENTRYPOINT ["./app_manager.sh"]
# 使用 CMD 允许用户在运行容器时覆盖默认命令
CMD ["./app_manager.sh"]

# 暴露 SSH 端口，尽管工具本身不直接监听，但如果需要从外部 SSH 进入容器调试则有用
# EXPOSE 22
