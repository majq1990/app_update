#!/bin/bash

# 获取脚本所在的目录
SCRIPT_DIR=$(dirname "$0")
cd "$SCRIPT_DIR" || exit 1 # 进入脚本目录，如果失败则退出

# 定义容器内的应用路径
CONTAINER_APP_PATH=/app/app_updater

echo '--- 正在启动 Docker 容器并进入应用管理菜单 ---'

# 检查 SSH 代理是否已启动
if [ -z "$SSH_AUTH_SOCK" ]; then
    echo '未检测到 SSH 代理，尝试启动 SSH 代理...'
    eval "$(ssh-agent -s)" # 启动 SSH 代理并设置环境变量
    if [ $? -ne 0 ]; then
        echo '错误: SSH 代理启动失败。'
        exit 1
    else
        echo 'SSH 代理已启动。'
    fi
fi

# 检查 SSH 代理中是否已加载密钥
# ssh-add -l 会列出已加载的密钥，如果没有任何密钥，它会返回非零退出状态
if ! ssh-add -l >/dev/null 2>&1; then
    echo 'SSH 代理中未加载密钥，尝试添加 ~/.ssh/id_rsa...'
    # 检查私钥文件是否存在
    if [ -f "$HOME/.ssh/id_rsa" ]; then
        ssh-add "$HOME/.ssh/id_rsa"
        # 检查 ssh-add 命令的退出状态
        if [ $? -ne 0 ]; then
            echo '警告: 添加 ~/.ssh/id_rsa 失败。请检查密钥文件权限或密码。'
        else
            echo 'SSH 代理中已加载密钥。'
        fi
    else
        echo '警告: 未找到 ~/.ssh/id_rsa 私钥文件。请确保已生成SSH密钥对。'
    fi
else
    echo 'SSH 代理中已加载密钥。'
fi

# 获取当前工作目录，用于 Docker 卷挂载
CURRENT_DIR=$(pwd)

# 运行 Docker 容器
# -it: 交互式并分配一个伪终端
# --rm: 容器退出时自动删除
# -v "$CURRENT_DIR":/app/app_updater: 将当前目录挂载到容器内的 /app/app_updater
# -v "$SSH_AUTH_SOCK":/ssh-agent: 将 SSH 代理的 socket 挂载到容器内
# -e SSH_AUTH_SOCK=/ssh-agent: 在容器内设置 SSH_AUTH_SOCK 环境变量
# -e TZ=Asia/Singapore: 设置容器时区为亚洲/新加坡
# 最后添加要执行的命令：在容器内运行 app_manager.sh
docker run -it --rm \
    -v "$CURRENT_DIR":/app/app_updater \
    -v "$SSH_AUTH_SOCK":/ssh-agent \
    -e SSH_AUTH_SOCK=/ssh-agent \
    -e TZ=Asia/Singapore \
    java-app-updater \
    bash "${CONTAINER_APP_PATH}/app_manager.sh"
    # 或者如果 app_manager.sh 是可执行的并且在容器的 PATH 中，可以简化为：
    # java-app-updater app_manager.sh

# 脚本执行完毕，如果 SSH 代理是由本脚本启动的，可以考虑在这里停止它
# 但是由于 --rm 选项，容器退出后，SSH 代理的 socket 可能会失效，通常不需要手动停止
# 如果需要停止，可以添加 kill "$SSH_AGENT_PID"

