import os
import time
import subprocess # Import subprocess module
from .utils import load_config, execute_remote_command, execute_rsync, check_uri_availability, get_input, BACKUP_DIR
import logging

def run_rollback_process(config):
    '''
    执行应用回滚过程。
    参数:
        config (dict): 从config.yaml加载的配置数据。
    '''
    if not config:
        return

    webs = config.get("webs", [])
    if not webs:
        logging.info("配置文件中没有找到任何应用配置。")
        return

    logging.info("\n--- 选择要回滚的应用 ---")
    for i, app in enumerate(webs):
        logging.info(f"{i+1}. {app['web']} ({app['middle_type']})")

    try:
        choice = int(get_input("请输入要回滚的应用编号")) - 1
        if not (0 <= choice < len(webs)):
            logging.warning("无效的应用编号。")
            return
    except ValueError:
        logging.warning("请输入有效的数字。")
        return

    selected_app = webs[choice]
    app_name = selected_app['web']

    app_backup_path = os.path.join(BACKUP_DIR, app_name)
    if not os.path.exists(app_backup_path):
        logging.info(f"没有找到应用 '{app_name}' 的备份。")
        return

    logging.info(f"\n--- 选择 {app_name} 的回滚版本 (日期) ---")
    # 过滤掉非目录项，并按日期倒序排序
    backup_versions = sorted([d for d in os.listdir(app_backup_path) if os.path.isdir(os.path.join(app_backup_path, d))], reverse=True)
    if not backup_versions:
        logging.info(f"应用 '{app_name}' 没有可用的备份版本。")
        return

    for i, version in enumerate(backup_versions):
        logging.info(f"{i+1}. {version}")

    try:
        version_choice = int(get_input("请输入要回滚的版本编号")) - 1
        if not (0 <= version_choice < len(backup_versions)):
            logging.warning("无效的版本编号。")
            return
    except ValueError:
        logging.warning("请输入有效的数字。")
        return

    selected_version = backup_versions[version_choice]
    logging.info(f"\n--- 开始回滚应用: {app_name} 到版本: {selected_version} ---")

    # 遍历Master和Update群组
    for group_name in ["master", "update", "static_page_group"]: # Added static_page_group
        logging.info(f"\n--- 处理 {app_name} 的 {group_name} 群组进行回滚 ---")
        group_hosts = selected_app.get(group_name, [])

        for host_info in group_hosts:
            host = host_info['host']
            web_path = host_info['web_path']
            stop_cmd = host_info['stop_cmd']
            start_cmd = host_info['start_cmd']
            check_uri = host_info['check_uri']
            service_port = host_info['service_port']
            # Get user and group for file ownership
            file_user = host_info.get('user', 'root')
            file_group = host_info.get('group', 'root')

            logging.info(f"\n处理主机: {host}")

            try:
                # Determine paths based on group type, similar to run_update.py
                local_backup_source_base_path = os.path.join(BACKUP_DIR, app_name, selected_version, host)
                remote_target_path = ""
                chown_target_path = ""

                if group_name == 'static_page_group':
                    # For static_page_group, web_path is already the app's root on static server
                    local_backup_source_path = os.path.join(local_backup_source_base_path, "nginx_deploy")
                    remote_target_path = web_path
                    chown_target_path = web_path
                    # Static group defaults to nginx user/group
                    file_user = host_info.get('user', 'nginx')
                    file_group = host_info.get('group', 'nginx')
                    stop_cmd = "" # Static pages don't usually have stop/start commands
                    start_cmd = ""
                    check_uri = ""
                    service_port = 0
                elif selected_app['middle_type'] == 'jar' and group_name in ['master', 'update']:
                    # For JAR app's master/update group, static_page_path is relevant
                    static_page_path_on_host = host_info.get('static_page_path', '')
                    if not static_page_path_on_host:
                        logging.warning(f"    - 警告: 主机 {host} ({group_name} 群组) 未配置 'static_page_path'。跳过此主机的JAR静态回滚。")
                        continue
                    local_backup_source_path = os.path.join(local_backup_source_base_path, "nginx_deploy", "static_jar_backup")
                    remote_target_path = os.path.join(web_path, static_page_path_on_host)
                    chown_target_path = remote_target_path # chown on the static content path
                else: # Tomcat master/update groups (main application code)
                    local_backup_source_path = os.path.join(local_backup_source_base_path, app_name)
                    remote_target_path = web_path
                    chown_target_path = web_path

                if not os.path.exists(local_backup_source_path):
                    logging.error(f"    - 错误: 主机 {host} 的备份路径 '{local_backup_source_path}' 不存在。跳过此主机。")
                    continue

                # 1. 执行stop_cmd (only for master/update groups, not static_page_group)
                if group_name in ["master", "update"]:
                    execute_remote_command(host, stop_cmd, "停止应用")
                    time.sleep(2) # 模拟停止时间

                # 2. 还原备份代码
                # Add --delete to ensure full synchronization
                execute_rsync(f"{local_backup_source_path}/", f"{remote_target_path}/", host, "从本地备份还原代码到远程", ["--delete"])

                # --- Diagnostic: Verify remote directory content after rsync ---
                logging.debug(f"    - 验证远程目录 {remote_target_path} 内容 (rsync后):")
                try:
                    result = subprocess.run(['ssh', f'{host}', f'ls -la {remote_target_path}'], capture_output=True, text=True, check=True, timeout=10)
                    logging.debug(f"      远程目录内容:\n{result.stdout.strip()}")
                    if result.stderr:
                        logging.debug(f"      远程目录 stderr:\n{result.stderr.strip()}")
                except Exception as e:
                    logging.debug(f"      获取远程目录内容失败: {e}")
                # --- End Diagnostic ---

                # 3. 更新文件所属用户和用户组
                chown_cmd = f"chown -R {file_user}:{file_group} {chown_target_path}"
                execute_remote_command(host, chown_cmd, "更新文件所属用户和用户组")

                # 4. 执行start_cmd并检查 (only for master/update groups, not static_page_group)
                if group_name in ["master", "update"]:
                    execute_remote_command(host, start_cmd, "启动应用")
                    time.sleep(5) # 模拟启动时间

                    timeout_minutes = 5 if selected_app['middle_type'] == 'tomcat' and group_name == 'master' else 1
                    if check_uri_availability(check_uri, host, service_port, app_name, selected_app['middle_type'], timeout_minutes):
                        logging.info(f"    - {app_name} 在 {host} 上回滚成功并启动验证通过！")
                    else:
                        logging.error(f"    - {app_name} 在 {host} 上回滚后启动验证失败！请手动检查。")
                else: # For static_page_group, just confirm completion
                    logging.info(f"    - {app_name} 在 {host} 上静态页面回滚成功！")

            except Exception as e:
                logging.error(f"    - 错误: 处理主机 {host} 时发生异常: {e}")
                logging.error(f"    - 请检查SSH连接、权限、路径和命令是否正确。")

    logging.info(f"\n--- 应用 {app_name} 回滚过程完成 ---")

if __name__ == "__main__":
    logging.info("欢迎使用应用更新工具 - 回滚执行器！")
    config = load_config()
    if config:
        run_rollback_process(config)

