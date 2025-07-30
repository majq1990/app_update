
#!/bin/bash

# 定义Python脚本所在的目录
# 假设Python脚本 (generate_config.py, run_update.py, run_rollback.py, utils.py)
# 都在 'scripts/' 子目录中
SCRIPTS_DIR="scripts"

# 定义Python脚本的完整路径
GENERATE_CONFIG_MODULE="scripts.generate_config"
RUN_UPDATE_MODULE="scripts.run_update"
RUN_ROLLBACK_MODULE="scripts.run_rollback"

# 检查Python脚本是否存在
check_scripts() {
    # 检查模块文件是否存在，而不是直接执行的脚本
    if [ ! -f "${SCRIPTS_DIR}/generate_config.py" ]; then
        echo "错误: 找不到 ${SCRIPTS_DIR}/generate_config.py。请确保所有Python脚本都在 '${SCRIPTS_DIR}/' 目录中。"
        exit 1
    fi
    if [ ! -f "${SCRIPTS_DIR}/run_update.py" ]; then
        echo "错误: 找不到 ${SCRIPTS_DIR}/run_update.py。请确保所有Python脚本都在 '${SCRIPTS_DIR}/' 目录中。"
        exit 1
    fi
    if [ ! -f "${SCRIPTS_DIR}/run_rollback.py" ]; then
        echo "错误: 找不到 ${SCRIPTS_DIR}/run_rollback.py。请确保所有Python脚本都在 '${SCRIPTS_DIR}/' 目录中。"
        exit 1
    fi
    # 确保 utils.py 也存在，因为其他脚本依赖它
    if [ ! -f "${SCRIPTS_DIR}/utils.py" ]; then
        echo "错误: 找不到 ${SCRIPTS_DIR}/utils.py。请确保它在 '${SCRIPTS_DIR}/' 目录中。"
        exit 1
    fi
    # 确保 __init__.py 存在，使 scripts 目录成为一个包
    if [ ! -f "${SCRIPTS_DIR}/__init__.py" ]; then
        echo "错误: 找不到 ${SCRIPTS_DIR}/__init__.py。请确保它在 '${SCRIPTS_DIR}/' 目录中，以使 'scripts' 成为一个Python包。"
        exit 1
    fi
}

# 显示主菜单
show_menu() {
    echo ""
    echo "--- Java 应用更新工具 ---"
    echo "1. 生成/更新配置文件 (config.yaml)"
    echo "2. 执行应用更新"
    echo "3. 执行应用回滚"
    echo "4. 退出"
    echo "-------------------------"
    read -p "请输入您的选择 (1-4): " choice
}

# 主循环
main() {
    # 切换到脚本所在的目录，确保相对路径正确
    # 这对于从任何位置调用 app_manager.sh 都很重要
    # 获取当前脚本的目录
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    cd "$SCRIPT_DIR" || { echo "无法进入脚本目录: $SCRIPT_DIR"; exit 1; }

    check_scripts
    while true; do
        show_menu
        case $choice in
            1)
                echo ""
                echo ">>> 正在启动配置文件生成器..."
                python3 -m "$GENERATE_CONFIG_MODULE"
                ;;
            2)
                echo ""
                echo ">>> 正在启动应用更新程序..."
                python3 -m "$RUN_UPDATE_MODULE"
                ;;
            3)
                echo ""
                echo ">>> 正在启动应用回滚程序..."
                python3 -m "$RUN_ROLLBACK_MODULE"
                ;;
            4)
                echo ""
                echo "感谢使用，再见！"
                exit 0
                ;;
            *)
                echo ""
                echo "无效的选择，请重新输入。"
                ;;
        esac
        echo ""
        read -p "按任意键继续..." -n 1 -s
        echo ""
    done
}

# 执行主函数
main
