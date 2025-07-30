import yaml
import os
import sys # Import sys for stdout flushing
from .utils import load_config, execute_remote_command, setup_passwordless_ssh, CONFIG_FILE, get_input, setup_logging # Changed to relative import, added setup_logging
import logging # Import logging

def save_config(config_data):
    '''
    保存配置数据到config.yaml文件。
    参数:
        config_data (dict): 要保存的配置数据。
    '''
    try:
        # 确保配置目录存在
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True, indent=2)
        logging.info(f"\n配置文件 '{CONFIG_FILE}' 已成功保存！")
    except Exception as e:
        logging.error(f"保存配置文件时发生错误: {e}")

def create_new_application_config(ansible_user, ansible_ssh_pass, ansible_ssh_port):
    '''
    交互式创建单个应用的配置。
    参数:
        ansible_user (str): Ansible连接的用户名。
        ansible_ssh_pass (str): Ansible连接的密码。
        ansible_ssh_port (int): Ansible连接的SSH端口。
    返回:
        dict: 单个应用的配置字典。
    '''
    logging.info("\n--- 配置新应用 ---")

    web_name = get_input("请输入应用名称 (例如: eUrbanMIS, wukong)")

    # 检查应用名是否已存在
    current_config = load_config()
    if current_config and web_name in [app['web'] for app in current_config.get('webs', [])]:
        logging.warning(f"应用 '{web_name}' 已存在。请选择管理现有应用或输入其他名称。")
        return None

    middle_type = get_input("请输入中间件类型 (例如: tomcat, jar)", "tomcat") # REMOVED 'nginx' from example
    host = get_input("请输入主机IP (例如: 127.0.0.1)")
    web_path = get_input("请输入web部署路径 (例如: /egova/web/eUrbanMIS 或 /egova/web/nginx_deploy/eUrbanMIS)")


    # 停止和启动命令根据中间件类型提供默认值
    stop_cmd = ""
    start_cmd = ""
    if middle_type == "tomcat":
        stop_cmd = get_input("请输入停止命令 (例如: systemctl stop tomcat-MIS)", f"systemctl stop tomcat-{web_name.split('eUrban')[-1]}")
        start_cmd = get_input("请输入启动命令 (例如: systemctl start tomcat-MIS)", f"systemctl start tomcat-{web_name.split('eUrban')[-1]}")
    # REMOVED nginx specific stop/start commands
    # elif middle_type == "nginx":
    #     stop_cmd = get_input("请输入停止命令 (例如: systemctl stop nginx)", "systemctl stop nginx")
    #     start_cmd = get_input("请输入启动命令 (例如: systemctl start nginx)", "systemctl start nginx")
    elif middle_type == "jar":
        stop_cmd = get_input("请输入停止命令 (例如: systemctl stop myapp.service)", f"systemctl stop {web_name}.service")
        start_cmd = get_input("请输入启动命令 (例如: systemctl start myapp.service)", f"systemctl start {web_name}.service")
    
    check_uri = get_input("请输入健康检查URI (例如: /eUrbanMIS/main.htm 或 /)", "/")
    service_port = int(get_input("请输入服务端口 (例如: 8081, 8085)", "8081"))
    
    file_user = get_input("请输入文件所属用户 (默认为root)", "root")
    file_group = get_input("请输入文件所属用户组 (默认为root)", "root")

    # 询问是否设置SSH免密登录
    setup_ssh = get_input("是否现在设置SSH免密登录? (y/n)", "n").lower()
    if setup_ssh == 'y':
        if not setup_passwordless_ssh(host, ansible_user, ansible_ssh_pass, ansible_ssh_port):
            logging.warning("SSH免密设置失败，请手动配置或稍后重试。")

    # 添加排除文件和保留配置文件
    # Ensure these are joined from lists for display, and then split back into lists for storage
    master_exclusive_files_str = get_input("请输入Master群组需要排除的文件或目录 (多个用逗号分隔，相对于web部署路径，例如: egova-liquibase-[0-9]*.[0-9]*.[0-9]*.jar,egova-jobmanager-[0-9]*.[0-9]*.[0-9]*.jar)", "egova-liquibase-[0-9]*.[0-9]*.[0-9]*.jar,egova-jobmanager-[0-9]*.[0-9]*.[0-9]*.jar")
    retained_config_file_str = get_input("请输入应用级别保留的配置文件或目录 (多个用逗号分隔，相对于web部署路径，例如: WEB-INF/classes/jdbc.properties)", "WEB-INF/classes/jdbc.properties,WEB-INF/classes/redis.properties")
    log_dir = get_input("请输入应用级别日志目录 (相对于web部署路径，例如: WEB-INF/logs)", "")
    static_page_path = ""
    if middle_type == "jar":
        static_page_path = get_input("请输入JAR应用内部静态文件路径 (例如: view/navigator-map)", "")

    # 静态页面群组配置
    static_page_group_hosts = []
    add_static_host = get_input("是否为静态页面群组添加主机? (y/n)", "n").lower()
    while add_static_host == 'y':
        logging.info("\n--- 配置静态页面群组主机 ---")
        static_host = get_input("请输入静态页面主机IP")
        static_web_path = get_input("请输入静态页面web部署路径 (例如: /egova/web/nginx_deploy/eUrbanMIS)")
        static_file_user = get_input("请输入静态文件所属用户 (默认为nginx)", "nginx")
        static_file_group = get_input("请输入静态文件所属用户组 (默认为nginx)", "nginx")
        static_page_group_hosts.append({
            'host': static_host,
            'web_path': static_web_path,
            'user': static_file_user,
            'group': static_file_group
        })
        add_static_host = get_input("是否继续添加静态页面群组主机? (y/n)", "n").lower()

    return {
        'web': web_name,
        'middle_type': middle_type,
        'master': [{'host': host, 'web_path': web_path, 'stop_cmd': stop_cmd, 'start_cmd': start_cmd, 'check_uri': check_uri, 'service_port': service_port, 'user': file_user, 'group': file_group, 'static_page_path': static_page_path}],
        'update': [], # 默认update群组为空，可在管理界面添加
        'master_exclusive_files': [f.strip() for f in master_exclusive_files_str.split(',') if f.strip()],
        'retained_config_file': [f.strip() for f in retained_config_file_str.split(',') if f.strip()],
        'log_dir': log_dir,
        'static_page_group': static_page_group_hosts
    }

def add_host_to_group(app, group_name, ansible_user, ansible_ssh_pass, ansible_ssh_port):
    '''
    向指定应用的指定群组添加主机。
    '''
    logging.info(f"\n--- 为应用 '{app['web']}' 的 '{group_name}' 群组添加主机 ---")

    host = get_input("请输入主机IP")
    web_path = get_input("请输入web部署路径")
    stop_cmd = get_input("请输入停止命令")
    start_cmd = get_input("请输入启动命令")
    check_uri = get_input("请输入健康检查URI", "/")
    service_port = int(get_input("请输入服务端口", "8080"))
    file_user = get_input("请输入文件所属用户 (默认为root)", "root")
    file_group = get_input("请输入文件所属用户组 (默认为root)", "root")
    static_page_path = ""
    if app['middle_type'] == "jar":
        static_page_path = get_input("请输入JAR应用内部静态文件路径 (例如: BOOT-INF/classes/static)", "")

    # 询问是否设置SSH免密登录
    setup_ssh = get_input("是否现在设置SSH免密登录? (y/n)", "n").lower()
    if setup_ssh == 'y':
        if not setup_passwordless_ssh(host, ansible_user, ansible_ssh_pass, ansible_ssh_port):
            logging.warning("SSH免密设置失败，请手动配置或稍后重试。")

    app[group_name].append({
        'host': host,
        'web_path': web_path,
        'stop_cmd': stop_cmd,
        'start_cmd': start_cmd,
        'check_uri': check_uri,
        'service_port': service_port,
        'user': file_user,
        'group': file_group,
        'static_page_path': static_page_path
    })
    logging.info(f"主机 {host} 已添加到 '{group_name}' 群组。")

def manage_application_hosts(app, config_data):
    '''
    管理单个应用的Master和Update群组主机。
    '''
    while True:
        logging.info(f"\n--- 管理应用 '{app['web']}' 的主机 ---")
        logging.info("1. 查看 Master 群组主机")
        logging.info("2. 添加 Master 群组主机")
        logging.info("3. 删除 Master 群组主机")
        logging.info("4. 查看 Update 群组主机")
        logging.info("5. 添加 Update 群组主机")
        logging.info("6. 删除 Update 群组主机")
        logging.info("7. 查看静态页面群组主机")
        logging.info("8. 添加静态页面群组主机")
        logging.info("9. 删除静态页面群组主机")
        logging.info("10. 返回上一级")

        choice = get_input("请输入您的选择 (1-10)", "10")

        if choice == '1':
            logging.info(f"\n--- 应用 '{app['web']}' 的 Master 群组主机 ---")
            if app.get('master'):
                for i, host_info in enumerate(app['master']):
                    _display_host_details(host_info, i + 1, "Master") # 调用辅助函数显示完整信息
            else:
                logging.info("Master 群组没有配置主机。")
        elif choice == '2':
            add_host_to_group(app, 'master', config_data["ansible_user"], config_data["ansible_ssh_pass"], config_data["ansible_ssh_port"])
        elif choice == '3':
            if app.get('master'):
                logging.info("\n--- 选择要删除的 Master 群组主机 ---")
                for i, host_info in enumerate(app['master']):
                    logging.info(f"{i+1}. 主机: {host_info['host']}, 路径: {host_info['web_path']}, 用户: {host_info.get('user', 'N/A')}, 用户组: {host_info.get('group', 'N/A')}")
                try:
                    del_choice = int(get_input("请输入要删除的主机编号")) - 1
                    if 0 <= del_choice < len(app['master']):
                        deleted_host = app['master'].pop(del_choice)
                        logging.info(f"主机 {deleted_host['host']} 已从 Master 群组删除。")
                    else:
                        logging.warning("无效的主机编号。")
                except ValueError:
                    logging.warning("请输入有效的数字。")
            else:
                logging.info("Master 群组没有主机可删除。")
        elif choice == '4':
            logging.info(f"\n--- 应用 '{app['web']}' 的 Update 群组主机 ---")
            if app.get('update'):
                for i, host_info in enumerate(app['update']):
                    _display_host_details(host_info, i + 1, "Update") # 调用辅助函数显示完整信息
            else:
                logging.info("Update 群组没有配置主机。")
        elif choice == '5':
            add_host_to_group(app, 'update', config_data["ansible_user"], config_data["ansible_ssh_pass"], config_data["ansible_ssh_port"])
        elif choice == '6':
            if app.get('update'):
                logging.info("\n--- 选择要删除的 Update 群组主机 ---")
                for i, host_info in enumerate(app['update']):
                    logging.info(f"{i+1}. 主机: {host_info['host']}, 路径: {host_info['web_path']}, 用户: {host_info.get('user', 'N/A')}, 用户组: {host_info.get('group', 'N/A')}")
                try:
                    del_choice = int(get_input("请输入要删除的主机编号")) - 1
                    if 0 <= del_choice < len(app['update']):
                        deleted_host = app['update'].pop(del_choice)
                        logging.info(f"主机 {deleted_host['host']} 已从 Update 群组删除。")
                    else:
                        logging.warning("无效的主机编号。")
                except ValueError:
                    logging.warning("请输入有效的数字。")
            else:
                logging.info("Update 群组没有主机可删除。")
        elif choice == '7':
            logging.info(f"\n--- 应用 '{app['web']}' 的静态页面群组主机 ---")
            if app.get('static_page_group'):
                for i, host_info in enumerate(app['static_page_group']):
                    # MODIFIED: Reverted to specific print for static_page_group
                    logging.info(f"  {i+1}. 主机: {host_info['host']}")
                    logging.info(f"     Web路径: {host_info['web_path']}")
                    logging.info(f"     文件用户: {host_info.get('user', 'N/A')}")
                    logging.info(f"     文件用户组: {host_info.get('group', 'N/A')}")
            else:
                logging.info("静态页面群组没有配置主机。")
        elif choice == '8':
            add_host_to_group(app, 'static_page_group', config_data["ansible_user"], config_data["ansible_ssh_pass"], config_data["ansible_ssh_port"])
        elif choice == '9':
            if app.get('static_page_group'):
                logging.info("\n--- 选择要删除的静态页面群组主机 ---")
                for i, host_info in enumerate(app['static_page_group']):
                    logging.info(f"{i+1}. 主机: {host_info['host']}, 路径: {host_info['web_path']}, 用户: {host_info.get('user', 'N/A')}, 用户组: {host_info.get('group', 'N/A')}")
                try:
                    del_choice = int(get_input("请输入要删除的主机编号")) - 1
                    if 0 <= del_choice < len(app['static_page_group']):
                        deleted_host = app['static_page_group'].pop(del_choice)
                        logging.info(f"主机 {deleted_host['host']} 已从静态页面群组删除。")
                    else:
                        logging.warning("无效的主机编号。")
                except ValueError:
                    logging.warning("请输入有效的数字。")
            else:
                logging.info("静态页面群组没有主机可删除。")
        elif choice == '10':
            break
        else:
            logging.warning("无效的选择，请重新输入。")

def manage_existing_applications(config_data):
    '''
    管理现有应用（修改或删除）。
    '''
    webs = config_data.get("webs", [])
    if not webs:
        logging.info("没有可管理的应用。")
        return

    while True:
        logging.info("\n--- 管理现有应用 ---")
        for i, app in enumerate(webs):
            logging.info(f"{i+1}. {app['web']} ({app['middle_type']})")
        logging.info(f"{len(webs)+1}. 返回主菜单")

        try:
            choice = int(get_input(f"请输入要管理的应用编号 (1-{len(webs)+1})")) - 1
            if choice == len(webs):
                break # 返回主菜单
            if not (0 <= choice < len(webs)):
                logging.warning("无效的应用编号。")
                continue
        except ValueError:
            logging.warning("请输入有效的数字。")
            continue

        selected_app = webs[choice]
        
        # --- Display current application configuration immediately after selection ---
        logging.info(f"\n--- 当前应用 '{selected_app['web']}' 的详细配置 ---")
        logging.info(f"  应用名称: {selected_app['web']}")
        logging.info(f"  中间件类型: {selected_app['middle_type']}")
        
        master_exclusive_files_str_display = ','.join(selected_app.get('master_exclusive_files', []))
        retained_config_file_str_display = ','.join(selected_app.get('retained_config_file', []))
        
        logging.info(f"  Master群组排除文件: {master_exclusive_files_str_display}")
        logging.info(f"  保留配置文件: {retained_config_file_str_display}")
        logging.info(f"  日志目录: {selected_app.get('log_dir', 'N/A')}")

        # Display Master Group Hosts
        logging.info(f"\n  --- Master 群组主机 ({selected_app['web']}) ---")
        if selected_app.get('master'):
            for i, host_info in enumerate(selected_app['master']):
                _display_host_details(host_info, i + 1, "Master")
        else:
            logging.info("    Master 群组没有配置主机。")

        # Display Update Group Hosts
        logging.info(f"\n  --- Update 群组主机 ({selected_app['web']}) ---")
        if selected_app.get('update'):
            for i, host_info in enumerate(selected_app['update']):
                _display_host_details(host_info, i + 1, "Update")
        else:
            logging.info("    Update 群组没有配置主机。")

        # Display Static Page Group Hosts
        logging.info(f"\n  --- 静态页面群组主机 ({selected_app['web']}) ---")
        if selected_app.get('static_page_group'):
            for i, host_info in enumerate(selected_app['static_page_group']):
                # MODIFIED: Reverted to specific print for static_page_group
                logging.info(f"  {i+1}. 主机: {host_info['host']}")
                logging.info(f"     Web路径: {host_info['web_path']}")
                logging.info(f"     文件用户: {host_info.get('user', 'N/A')}")
                logging.info(f"     文件用户组: {host_info.get('group', 'N/A')}")
        else:
            logging.info("    静态页面群组没有配置主机。")
        # --- END NEW ---

        while True:
            logging.info(f"\n--- 管理应用: {selected_app['web']} ---")
            logging.info("1. 修改应用配置")
            logging.info("2. 管理主机群组")
            logging.info("3. 删除应用")
            logging.info("4. 返回上一级")

            app_manage_choice = get_input("请输入您的选择 (1-4)", "4")

            if app_manage_choice == '1':
                modify_application_config(selected_app)
            elif app_manage_choice == '2':
                manage_application_hosts(selected_app, config_data)
            elif app_manage_choice == '3':
                confirm = get_input(f"确定要删除应用 '{selected_app['web']}' 吗? (y/n)", "n").lower()
                if confirm == 'y':
                    webs.pop(choice)
                    logging.info(f"应用 '{selected_app['web']}' 已删除。")
                    break # 返回到管理现有应用列表
                else:
                    logging.info("取消删除。")
            elif app_manage_choice == '4':
                break # 返回到管理现有应用列表
            else:
                logging.warning("无效的选择，请重新输入。")

def _display_host_details(host_info, index, group_name):
    """Helper function to display details of a single host."""
    logging.info(f"  {index}. 主机: {host_info['host']}")
    logging.info(f"     Web路径: {host_info['web_path']}")
    # Only display stop/start commands, check_uri, service_port if they exist
    # and are typically relevant for application servers (Master/Update groups).
    # For Static Page Group, these might be empty or default, but we still print if key exists.
    if 'stop_cmd' in host_info:
        logging.info(f"     停止命令: {host_info['stop_cmd']}")
    if 'start_cmd' in host_info:
        logging.info(f"     启动命令: {host_info['start_cmd']}")
    if 'check_uri' in host_info:
        logging.info(f"     健康检查URI: {host_info['check_uri']}")
    if 'service_port' in host_info:
        logging.info(f"     服务端口: {host_info['service_port']}")
    
    logging.info(f"     文件用户: {host_info.get('user', 'N/A')}")
    logging.info(f"     文件用户组: {host_info.get('group', 'N/A')}")
    if 'static_page_path' in host_info and host_info['static_page_path']:
        logging.info(f"     JAR静态文件路径: {host_info['static_page_path']}")

def modify_application_config(app):
    '''
    修改单个应用的配置。
    '''
    logging.info(f"\n--- 修改应用 '{app['web']}' 的配置 ---")

    # --- REMOVED: Display current application configuration from here ---
    # This block is now in manage_existing_applications for immediate display.

    logging.info(f"\n--- 请输入新的配置值 (按回车键保留当前值) ---")

    app['middle_type'] = get_input(f"修改中间件类型 (当前: {app['middle_type']})", app['middle_type'])
    
    # 统一处理 master_exclusive_files, retained_config_file, log_dir
    # 确保它们在配置中是列表形式
    # When displaying, join the list elements with a comma
    master_exclusive_files_str_display = ','.join(app.get('master_exclusive_files', []))
    retained_config_file_str_display = ','.join(app.get('retained_config_file', []))
    
    master_exclusive_files_str_input = get_input(f"修改Master群组排除文件 (当前: {master_exclusive_files_str_display})", master_exclusive_files_str_display)
    app['master_exclusive_files'] = [f.strip() for f in master_exclusive_files_str_input.split(',') if f.strip()]

    retained_config_file_str_input = get_input(f"修改保留配置文件 (当前: {retained_config_file_str_display})", retained_config_file_str_display)
    app['retained_config_file'] = [f.strip() for f in retained_config_file_str_input.split(',') if f.strip()]

    app['log_dir'] = get_input(f"修改日志目录 (当前: {app.get('log_dir', '')})", app.get('log_dir', ''))

    # 更新master和update群组中的static_page_path (仅针对jar应用)
    if app['middle_type'] == 'jar':
        current_static_page_path = ""
        # 尝试从第一个master主机获取当前static_page_path
        if app.get('master') and app['master'][0].get('static_page_path'):
            current_static_page_path = app['master'][0]['static_page_path']
        
        new_static_page_path = get_input(f"修改JAR应用内部静态文件路径 (当前: {current_static_page_path})", current_static_page_path)
        
        for group in ['master', 'update']:
            for host_info in app.get(group, []):
                host_info['static_page_path'] = new_static_page_path
    
    logging.info(f"应用 '{app['web']}' 配置修改成功！")

def modify_global_settings(config_data):
    '''
    修改全局设置。
    '''
    logging.info("\n--- 修改全局设置 ---")

    config_data["ansible_user"] = get_input(f"修改Ansible连接用户 (当前: {config_data['ansible_user']})", config_data["ansible_user"])
    config_data["ansible_ssh_pass"] = get_input(f"修改Ansible连接密码 (当前: {'*' * len(config_data['ansible_ssh_pass']) if config_data['ansible_ssh_pass'] else '无'})", config_data["ansible_ssh_pass"])
    config_data["ansible_ssh_port"] = int(get_input(f"修改Ansible连接SSH端口 (当前: {config_data['ansible_ssh_port']})", str(config_data["ansible_ssh_port"])))
    
    # 确保 global_exclude_logs 在 config_data 中存在
    current_global_exclude_logs = config_data.get("global_exclude_logs", "")
    config_data["global_exclude_logs"] = get_input(f"修改全局排除日志模式 (多个用逗号分隔，当前: {current_global_exclude_logs})", current_global_exclude_logs)
    
    logging.info("全局设置修改成功！")

def main_menu():
    '''主菜单循环，提供配置生成、管理和保存功能。'''
    setup_logging() # <--- 新增：在主菜单开始时配置日志

    config_data = load_config()
    if config_data is None:
        # 如果config.yaml不存在或加载失败，则初始化一个空配置
        config_data = {
            "ansible_ssh_pass": "",
            "ansible_ssh_port": 22,
            "ansible_user": "root",
            "is_checked_successful": False,
            "webs": [],
            "global_exclude_logs": "*.log,logs/" # New default for global exclude logs
        }
        logging.info("未找到现有配置文件，已创建新的空配置。")

    # --- NEW: Display global settings by default ---
    logging.info(f"\n--- 当前全局设置 ---")
    logging.info(f"  Ansible连接用户: {config_data.get('ansible_user', 'N/A')}")
    # Mask password for display
    masked_pass = '*' * len(config_data.get('ansible_ssh_pass', '')) if config_data.get('ansible_ssh_pass') else '无'
    logging.info(f"  Ansible连接密码: {masked_pass}")
    logging.info(f"  Ansible连接SSH端口: {config_data.get('ansible_ssh_port', 'N/A')}")
    logging.info(f"  全局排除日志模式: {config_data.get('global_exclude_logs', 'N/A')}")
    # --- END NEW ---

    while True:
        logging.info("\n--- 配置文件生成器主菜单 ---")
        logging.info("1. 添加新应用")
        logging.info("2. 管理现有应用")
        logging.info("3. 修改全局设置")
        logging.info("4. 保存配置并退出")

        choice = get_input("请输入您的选择 (1-4)")

        if choice == '1':
            new_app = create_new_application_config(
                config_data["ansible_user"],
                config_data["ansible_ssh_pass"],
                config_data["ansible_ssh_port"]
            )
            if new_app:
                config_data["webs"].append(new_app)
        elif choice == '2':
            manage_existing_applications(config_data)
        elif choice == '3':
            modify_global_settings(config_data)
        elif choice == '4':
            save_config(config_data)
            logging.info("退出配置文件生成器。")
            break
        else:
            logging.warning("无效的选择，请重新输入。")

if __name__ == "__main__":
    logging.info("欢迎使用应用更新工具 - 配置文件生成器！")
    main_menu()

