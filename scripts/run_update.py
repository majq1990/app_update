import datetime
import os
import time
import subprocess
import shutil # Import shutil for directory operations
import glob # Import glob for pattern matching
import sys # Import sys module here
from .utils import load_config, execute_remote_command, execute_rsync, check_uri_availability, get_input, BACKUP_DIR, setup_logging # Added setup_logging
import logging

def process_group_update(app_name, middle_type, master_exclusive_files, global_exclude_logs_param, app_log_dir, app_retained_config_file_param, current_date, group_name, group_hosts):
    '''
    处理单个群组的更新逻辑（实际执行）。
    参数:
        app_name (str): 应用名称。
        middle_type (str): 中间件类型。
        master_exclusive_files (list): Master群组排除文件列表。
        global_exclude_logs_param (str/list): 全局排除的日志文件模式字符串或列表。
        app_log_dir (str): 应用级别的日志目录相对路径。
        app_retained_config_file_param (str/list): 应用级别的保留配置文件相对路径字符串或列表。
        current_date (str): 当前日期字符串。
        group_name (str): 群组名称 ('master' 或 'update')。
        group_hosts (list): 群组中的主机列表。
    '''
    logging.info(f"\n--- 实际处理 {app_name} 的 {group_name} 群组 ---")
    for host_info in group_hosts:
        host = host_info['host']
        web_path = host_info['web_path']
        stop_cmd = host_info['stop_cmd']
        start_cmd = host_info['start_cmd']
        check_uri = host_info['check_uri']
        service_port = host_info['service_port']
        file_user = host_info.get('user', 'root')
        file_group = host_info.get('group', 'root')

        logging.info(f"\n实际处理主机: {host}")

        try:
            # 1. 执行stop_cmd
            execute_remote_command(host, stop_cmd, "停止应用")
            time.sleep(2) # 等待停止

            # 2. 备份当前代码
            local_backup_path_with_app = os.path.join(BACKUP_DIR, app_name, current_date, host, app_name)
            os.makedirs(local_backup_path_with_app, exist_ok=True)

            # 备份时排除选项
            backup_exclude_options_list = []
            
            # --- 修正: 健壮处理 global_exclude_logs_param ---
            global_exclude_items = []
            if isinstance(global_exclude_logs_param, list):
                global_exclude_items = global_exclude_logs_param
            elif isinstance(global_exclude_logs_param, str):
                global_exclude_items = [f.strip() for f in global_exclude_logs_param.split(',') if f.strip()]
            
            for f_stripped in global_exclude_items:
                backup_exclude_options_list.append(f"--exclude={f_stripped}")
            # --- 修正结束 ---

            if app_log_dir: # 排除应用级别的日志目录
                app_log_dir_stripped = app_log_dir.strip()
                if app_log_dir_stripped:
                    # 确保排除目录本身和目录内容，移除额外的引号
                    backup_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/")
                    backup_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/*")

            execute_rsync(f"{web_path}/", local_backup_path_with_app, host, "备份远程代码到本地", backup_exclude_options_list)

            # 3. 复制本地代码到远程主机 (直接覆盖并删除不匹配内容，但保留排除项)
            local_update_source_path = os.path.join("update", app_name) + os.sep
            logging.info(f"    - 本地更新源路径为: {local_update_source_path}")

            update_exclude_options_list = []
            if app_log_dir: # 更新时排除应用级别的日志目录
                app_log_dir_stripped = app_log_dir.strip()
                if app_log_dir_stripped:
                    update_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/")
                    update_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/*")
            
            # --- 修正: 健壮处理 app_retained_config_file_param ---
            retained_config_items = []
            if isinstance(app_retained_config_file_param, list):
                retained_config_items = app_retained_config_file_param
            elif isinstance(app_retained_config_file_param, str):
                retained_config_items = [f.strip() for f in app_retained_config_file_param.split(',') if f.strip()]
            
            for f_stripped in retained_config_items:
                update_exclude_options_list.append(f"--exclude={f_stripped}")
            # --- 修正结束 ---

            if middle_type == "tomcat" and group_name == "update" and master_exclusive_files:
                # --- 新增调试日志：打印 master_exclusive_files 的内容和类型 ---
                logging.debug(f"DEBUG: master_exclusive_files content: {master_exclusive_files}")
                for i, item in enumerate(master_exclusive_files):
                    logging.debug(f"DEBUG: master_exclusive_files[{i}] type: {type(item)}, value: {item}")
                # --- 调试日志结束 ---
                for f in master_exclusive_files: # master_exclusive_files 已经是列表
                    # 确保 f 是字符串才调用 strip()
                    f_stripped = f.strip() if isinstance(f, str) else str(f)
                    if f_stripped:
                        update_exclude_options_list.append(f"--exclude={f_stripped}")
                logging.info(f"    - Tomcat Update群组，将额外排除文件: {', '.join([str(x) for x in master_exclusive_files])}") # 确保join的是字符串

            execute_rsync(local_update_source_path, f"{web_path}/", host, "复制更新代码", update_exclude_options_list)

            # --- Diagnostic: Verify remote directory content after rsync ---
            logging.debug(f"    - 验证远程目录 {web_path} 内容 (rsync后):\n")
            try:
                result = subprocess.run(['ssh', f'{host}', f'ls -la {web_path}'], capture_output=True, text=True, check=True, timeout=10)
                logging.debug(f"      远程目录内容:\n{result.stdout.strip()}")
                if result.stderr:
                    logging.debug(f"      远程目录 stderr:\n{result.stderr.strip()}")
            except Exception as e:
                logging.debug(f"      获取远程目录内容失败: {e}")
            # --- End Diagnostic ---

            # 4. 更新文件所属用户和用户组
            chown_cmd = f"chown -R {file_user}:{file_group} {web_path}"
            execute_remote_command(host, chown_cmd, "更新文件所属用户和用户组")

            # 5. 执行start_cmd并检查
            execute_remote_command(host, start_cmd, "启动应用")
            initial_timeout = 5 if middle_type == 'tomcat' and group_name == 'master' else 1
            if check_uri_availability(check_uri, host, service_port, app_name, middle_type, initial_timeout):
                logging.info(f"    - {app_name} 在 {host} 上更新成功并启动验证通过！")
            else:
                logging.error(f"    - {app_name} 在 {host} 上更新后启动验证失败！请手动检查。")
        except Exception as e:
            logging.error(f"    - 错误: 实际执行主机 {host} 时发生异常: {e}")
            logging.error(f"    - 请检查SSH连接、权限和路径是否正确。")

def process_static_partial_update(app_name, static_update_path, groups_to_update_static, current_date, selected_app):
    '''
    处理静态页面部分更新逻辑。
    参数:
        app_name (str): 应用名称。
        static_update_path (str): 应用内的静态更新路径。
        groups_to_update_static (list): 需要更新的群组列表 (master, update, static_page_group)。
        current_date (str): 当前日期字符串。
        selected_app (dict): 当前选择的应用配置。
    '''
    logging.info(f"\n--- 开始处理 {app_name} 的静态页面部分更新 ---")
    
    local_update_source_base = os.path.join("update", app_name) # update/eUrbanMIS/
    local_static_source_path = os.path.join(local_update_source_base, static_update_path) # update/eUrbanMIS/view/some/path/

    if not os.path.exists(local_static_source_path):
        logging.error(f"错误: 本地静态更新源路径 '{local_static_source_path}' 不存在。请检查路径是否正确。")
        return

    for group_name in groups_to_update_static:
        group_hosts = selected_app.get(group_name, [])
        if not group_hosts:
            logging.warning(f"警告: {app_name} 的 {group_name} 群组没有配置主机。跳过静态部分更新。")
            continue

        for host_info in group_hosts:
            host = host_info['host']
            web_path = host_info['web_path']
            file_user = host_info.get('user', 'root')
            file_group = host_info.get('group', 'root')

            remote_base_path = "" # 远程目标路径的根
            remote_static_target_path = "" # 远程静态文件最终目标路径
            chown_target_path = "" # chown命令的目标路径

            if selected_app['middle_type'] == 'jar' and group_name in ['master', 'update']:
                remote_base_path = os.path.join(web_path, host_info.get('static_page_path', ''))
                remote_static_target_path = os.path.join(remote_base_path, static_update_path)
                chown_target_path = remote_base_path # chown作用于应用的静态根目录
            elif group_name == 'static_page_group':
                # web_path 已经是静态文件服务器上该应用的根路径 (例如: /egova/web/nginx_deploy/eUrbanMIS)
                remote_base_path = web_path
                remote_static_target_path = os.path.join(remote_base_path, static_update_path)
                chown_target_path = remote_base_path # chown作用于应用的静态根目录
            else: # Tomcat master/update groups
                remote_base_path = web_path # web_path 已经是应用的根目录 (例如: /egova/web/eUrbanMIS)
                remote_static_target_path = os.path.join(remote_base_path, static_update_path)
                chown_target_path = remote_base_path # chown作用于应用的根目录

            logging.info(f"\n处理主机: {host} ({group_name} 群组)")
            try:
                # 1. 备份对应路径
                # 根据群组类型设置备份路径
                if group_name == 'static_page_group':
                    local_backup_path_with_app = os.path.join(BACKUP_DIR, app_name, current_date, host, "nginx_deploy", static_update_path)
                else: # master and update groups
                    local_backup_path_with_app = os.path.join(BACKUP_DIR, app_name, current_date, host, app_name, static_update_path)

                os.makedirs(local_backup_path_with_app, exist_ok=True)
                execute_rsync(f"{remote_static_target_path}/", local_backup_path_with_app, host, f"备份远程静态页面路径 '{static_update_path}' 到本地")

                # 2. 覆盖过去 (添加 --delete)
                execute_rsync(f"{local_static_source_path}/", f"{remote_static_target_path}/", host, f"复制本地静态页面路径 '{static_update_path}' 到远程", ["--delete"])

                # 3. 更新文件所属用户和用户组
                execute_remote_command(host, f"chown -R {file_user}:{file_group} {chown_target_path}", "更新文件所属用户和用户组")
                logging.info(f"    - {app_name} 在 {host} 上静态页面部分更新成功！")

            except Exception as e:
                logging.error(f"    - 错误: 处理主机 {host} 静态页面部分更新时发生异常: {e}")
                logging.error(f"    - 请检查SSH连接、权限和路径是否正确。")

def _extract_static_files_eUrbanMIS_framework(app_name, local_app_update_dir):
    '''
    Extracts static files for eUrbanMIS or other framework applications
    based on pack_for_nginx_for_20230101.sh logic.
    '''
    logging.info(f"    - Executing static file extraction for {app_name} (eUrbanMIS/Framework type).")

    deploy_dir_base = os.path.join(local_app_update_dir, "nginx_deploy")
    deploy_dir_app = os.path.join(deploy_dir_base, app_name)

    # Clean up previous deploy_dir
    if os.path.exists(deploy_dir_base):
        shutil.rmtree(deploy_dir_base)
    os.makedirs(deploy_dir_app, exist_ok=True)

    dirs_to_copy = ("library", "other", "style", "view", "productionLibrary")
    
    # Extract META-INF/resources from JARs
    jar_files = glob.glob(os.path.join(local_app_update_dir, "WEB-INF", "lib", "egova-*.jar"))
    for jar in jar_files:
        logging.debug(f"      Extracting from JAR: {os.path.basename(jar)}")
        try:
            # Using subprocess to run unzip as shutil.unpack_archive might not handle META-INF/resources directly
            # Capture output and log as DEBUG, only log warnings/errors to console
            result = subprocess.run(["unzip", "-o", jar, "META-INF/resources/*", "-d", deploy_dir_app], 
                           check=True, capture_output=True, text=True)
            logging.debug(f"        Unzip stdout for {os.path.basename(jar)}:\n{result.stdout.strip()}")
            if result.stderr:
                logging.debug(f"        Unzip stderr for {os.path.basename(jar)}:\n{result.stderr.strip()}")

            # Move contents of META-INF/resources up to deploy_dir_app
            meta_inf_resources = os.path.join(deploy_dir_app, "META-INF", "resources")
            if os.path.exists(meta_inf_resources):
                for item in os.listdir(meta_inf_resources):
                    shutil.move(os.path.join(meta_inf_resources, item), deploy_dir_app)
                shutil.rmtree(os.path.join(deploy_dir_app, "META-INF")) # Clean up empty META-INF
        except subprocess.CalledProcessError as e:
            # Log the full error to debug, only a summary to warning for console
            logging.debug(f"        Error extracting from {os.path.basename(jar)}:\n{e.stderr.strip()}")
            # Changed logging.warning to logging.debug for these specific warnings
            logging.debug(f"      Warning: Failed to extract from {os.path.basename(jar)}: {e.stderr.splitlines()[0].strip()}") # Only show first line of error
        except Exception as e:
            # Changed logging.warning to logging.debug for these specific warnings
            logging.debug(f"      Warning: Error processing {os.path.basename(jar)}: {e}")

    # Copy additional directories
    for d in dirs_to_copy:
        source_dir = os.path.join(local_app_update_dir, d)
        target_dir = os.path.join(deploy_dir_app, d)
        if os.path.exists(source_dir):
            logging.debug(f"      Copying directory: {d}")
            shutil.copytree(source_dir, target_dir, dirs_exist_ok=True) # Use dirs_exist_ok for Python 3.8+
        else:
            logging.debug(f"      Directory not found, skipping: {d}")

    # Remove specific files
    for root, _, files in os.walk(deploy_dir_app):
        for f in files:
            if f.endswith(".xml"):
                os.remove(os.path.join(root, f))
            elif f.endswith(".jsp"): # find -name "*.jsp" | xargs rm -f
                os.remove(os.path.join(root, f))
    
    logging.info(f"    - Static file extraction for {app_name} completed.")


def _extract_static_files_eUrbanGIS(app_name, local_app_update_dir):
    '''
    Extracts static files for eUrbanGIS based on 220908090120_pack_gis_for_nginx.sh logic.
    '''
    logging.info(f"    - Executing static file extraction for {app_name} (eUrbanGIS type).")

    deploy_dir_base = os.path.join(local_app_update_dir, "nginx_deploy")
    deploy_dir_app = os.path.join(deploy_dir_base, app_name)

    # Clean up previous deploy_dir
    if os.path.exists(deploy_dir_base):
        shutil.rmtree(deploy_dir_base)
    os.makedirs(deploy_dir_app, exist_ok=True)

    dirs_to_copy = ("data", "data3d", "resourceCenter")

    # Extract META-INF/resources from JARs
    jar_files = glob.glob(os.path.join(local_app_update_dir, "WEB-INF", "lib", "egova-*.jar"))
    for jar in jar_files:
        logging.debug(f"      Extracting from JAR: {os.path.basename(jar)}")
        try:
            result = subprocess.run(["unzip", "-o", jar, "META-INF/resources/*", "-d", deploy_dir_app], 
                           check=True, capture_output=True, text=True)
            logging.debug(f"        Unzip stdout for {os.path.basename(jar)}:\n{result.stdout.strip()}")
            if result.stderr:
                logging.debug(f"        Unzip stderr for {os.path.basename(jar)}:\n{result.stderr.strip()}")

            # Move contents of META-INF/resources up to deploy_dir_app
            meta_inf_resources = os.path.join(deploy_dir_app, "META-INF", "resources")
            if os.path.exists(meta_inf_resources):
                for item in os.listdir(meta_inf_resources):
                    shutil.move(os.path.join(meta_inf_resources, item), deploy_dir_app)
                shutil.rmtree(os.path.join(deploy_dir_app, "META-INF")) # Clean up empty META-INF
        except subprocess.CalledProcessError as e:
            logging.debug(f"        Error extracting from {os.path.basename(jar)}:\n{e.stderr.strip()}")
            # Changed logging.warning to logging.debug for these specific warnings
            logging.debug(f"      Warning: Failed to extract from {os.path.basename(jar)}: {e.stderr.splitlines()[0].strip()}") # Only show first line of error
        except Exception as e:
            # Changed logging.warning to logging.debug for these specific warnings
            logging.debug(f"      Warning: Error processing {os.path.basename(jar)}: {e}")

    # Copy additional directories
    for d in dirs_to_copy:
        source_dir = os.path.join(local_app_update_dir, d)
        target_dir = os.path.join(deploy_dir_app, d)
        if os.path.exists(source_dir):
            logging.debug(f"      Copying directory: {d}")
            shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)
        else:
            logging.debug(f"      Directory not found, skipping: {d}")

    # Remove specific files
    for root, _, files in os.walk(deploy_dir_app):
        for f in files:
            if f.endswith(".xml"):
                os.remove(os.path.join(root, f))
            elif f.endswith(".jsp"): # find -name "*.jsp" | xargs rm -f
                os.remove(os.path.join(root, f))
    
    logging.info(f"    - Static file extraction for {app_name} completed.")


def process_static_full_update_tomcat(app_name, static_page_group_hosts, current_date, selected_app):
    '''
    处理Tomcat应用的静态页面全量更新逻辑。
    前置条件：Master和Update群组已更新。
    参数:
        app_name (str): 应用名称。
        static_page_group_hosts (list): 静态页面群组的主机列表。
        current_date (str): 当前日期字符串。
        selected_app (dict): 当前选择的应用配置。
    '''
    logging.info(f"\n--- 开始处理 {app_name} 的静态页面全量更新 (Tomcat) ---")

    local_app_update_dir = os.path.join("update", app_name) # e.g., update/eUrbanMIS
    local_nginx_deploy_dir = os.path.join(local_app_update_dir, "nginx_deploy", app_name) # e.g., update/eUrbanMIS/nginx_deploy/eUrbanMIS

    # 1. 执行静态文件提取逻辑 (Pythonized from shell scripts)
    logging.info(f"    - Performing static file extraction for {app_name} locally...")
    try:
        if app_name == "eUrbanGIS":
            _extract_static_files_eUrbanGIS(app_name, local_app_update_dir)
        else: # Default to eUrbanMIS/framework logic for other apps
            _extract_static_files_eUrbanMIS_framework(app_name, local_app_update_dir)
        logging.info("    - Local static file extraction completed successfully.")
    except Exception as e:
        logging.error(f"    - Error during local static file extraction: {e}")
        return

    if not os.path.exists(local_nginx_deploy_dir):
        logging.error(f"错误: 静态文件提取后目录 '{local_nginx_deploy_dir}' 不存在。静态文件提取可能失败。")
        return

    # 2. 推送覆盖完整的静态页面服务器的全应用路径
    if not static_page_group_hosts:
        logging.warning(f"警告: {app_name} 的静态页面群组没有配置主机。跳过静态全量更新。")
        return

    for host_info in static_page_group_hosts:
        host = host_info['host']
        web_path = host_info['web_path'] # This is the full application path on the static server
        file_user = host_info.get('user', 'nginx')
        file_group = host_info.get('group', 'nginx')

        # 远程静态文件根目录，例如 /egova/web/nginx_deploy/eUrbanMIS
        # web_path 已经是静态文件服务器上该应用的根路径 (例如: /egova/web/nginx_deploy/eUrbanMIS)
        # 修正: 移除 web_path 末尾的斜杠，避免双斜杠
        remote_static_app_root = web_path.rstrip('/')

        logging.info(f"\n处理静态页面服务器: {host}")
        try:
            # 备份远程静态页面根目录
            local_backup_path_full = os.path.join(BACKUP_DIR, app_name, current_date, host, "nginx_deploy", "static_full_backup")
            os.makedirs(local_backup_path_full, exist_ok=True)
            execute_rsync(f"{remote_static_app_root}/", local_backup_path_full, host, "备份远程静态页面根目录")

            # 推送本地提取的静态文件到远程静态服务器 (已包含 --delete)
            execute_rsync(f"{local_nginx_deploy_dir}/", f"{remote_static_app_root}/", host, "推送全量静态文件到远程", ["--delete"])

            # 更新文件所属用户和用户组
            execute_remote_command(host, f"chown -R {file_user}:{file_group} {remote_static_app_root}", "更新文件所属用户和用户组")
            logging.info(f"    - {app_name} 在 {host} 上静态页面全量更新成功！")

        except Exception as e:
            logging.error(f"    - 错误: 处理静态页面服务器 {host} 静态页面全量更新时发生异常: {e}")
            logging.error(f"    - 请检查SSH连接、权限和路径是否正确。")


def process_static_update_jar(app_name, static_update_source_path_local, groups_to_update_jar_static, current_date, selected_app):
    '''
    处理JAR类应用的静态页面更新逻辑。
    参数:
        app_name (str): 应用名称。
        static_update_source_path_local (str): 本地update目录内对应应用包内的静态文件总路径。
        groups_to_update_jar_static (list): 需要更新的群组列表 (master, update, static_page_group)。
        current_date (str): 当前日期字符串。
        selected_app (dict): 当前选择的应用配置。
    '''
    logging.info(f"\n--- 开始处理 {app_name} 的静态页面更新 (JAR) ---")

    if not os.path.exists(static_update_source_path_local):
        logging.error(f"错误: 本地静态更新源路径 '{local_static_source_path}' 不存在。请检查路径是否正确。")
        return

    for group_name in groups_to_update_jar_static:
        group_hosts = selected_app.get(group_name, [])
        if not group_hosts:
            logging.warning(f"警告: {app_name} 的 {group_name} 群组没有配置主机。跳过JAR静态更新。")
            continue

        for host_info in group_hosts:
            host = host_info['host']
            web_path = host_info['web_path']
            file_user = host_info.get('user', 'root')
            file_group = host_info.get('group', 'root')

            remote_destination_path = ""
            if group_name == 'static_page_group':
                # 对于静态页面服务器，目标是web_path (已包含应用名)
                # 修正: 移除 web_path 末尾的斜杠，避免双斜杠
                remote_destination_path = web_path.rstrip('/')
                file_user = host_info.get('user', 'nginx') # Static group defaults to nginx
                file_group = host_info.get('group', 'nginx')
            else:
                # 对于Master/Update群组，目标是web_path + static_page_path
                static_page_path_on_host = host_info.get('static_page_path', '')
                if not static_page_path_on_host:
                    logging.warning(f"警告: 主机 {host} ({group_name} 群组) 未配置 'static_page_path'。跳过此主机的JAR静态更新。")
                    continue
                remote_destination_path = os.path.join(web_path, static_page_path_on_host)

            logging.info(f"\n处理主机: {host} ({group_name} 群组)")
            try:
                # 1. 备份对应路径
                # 调整备份路径，使其统一存放在 nginx_deploy 目录下，并增加 static_jar_backup 标识
                local_backup_path_with_app = os.path.join(BACKUP_DIR, app_name, current_date, host, "nginx_deploy", "static_jar_backup")
                os.makedirs(local_backup_path_with_app, exist_ok=True)
                execute_rsync(f"{remote_destination_path}/", local_backup_path_with_app, host, f"备份远程静态页面路径 '{remote_destination_path}' 到本地")

                # 2. 覆盖过去 (添加 --delete)
                execute_rsync(f"{static_update_source_path_local}/", f"{remote_destination_path}/", host, f"复制本地静态文件到远程 '{remote_destination_path}'", ["--delete"])

                # 3. 更新文件所属用户和用户组
                execute_remote_command(host, f"chown -R {file_user}:{file_group} {remote_destination_path}", "更新文件所属用户和用户组")
                logging.info(f"    - {app_name} 在 {host} 上JAR静态页面更新成功！")

            except Exception as e:
                logging.error(f"    - 错误: 处理主机 {host} JAR静态页面更新时发生异常: {e}")
                logging.error(f"    - 请检查SSH连接、权限和路径是否正确。")


def simulate_group_update(app_name, middle_type, master_exclusive_files, global_exclude_logs_param, app_log_dir, app_retained_config_file_param, current_date, group_name, group_hosts):
    '''
    模拟处理单个群组的更新逻辑。
    参数:
        app_name (str): 应用名称。
        middle_type (str): 中间件类型。
        master_exclusive_files (list): Master群组排除文件列表。
        global_exclude_logs_param (str/list): 全局排除的日志文件模式字符串或列表。
        app_log_dir (str): 应用级别的日志目录相对路径。
        app_retained_config_file_param (str/list): 应用级别的保留配置文件相对路径字符串或列表。
        current_date (str): 当前日期字符串。
        group_name (str): 群组名称 ('master' 或 'update')。
        group_hosts (list): 群组中的主机列表。
    '''
    logging.info(f"\n--- 模拟处理 {app_name} 的 {group_name} 群组 ---")
    for host_info in group_hosts:
        host = host_info['host']
        web_path = host_info['web_path']
        stop_cmd = host_info['stop_cmd']
        start_cmd = host_info['start_cmd']
        check_uri = host_info['check_uri']
        service_port = host_info['service_port']
        file_user = host_info.get('user', 'root')
        file_group = host_info.get('group', 'root')

        logging.info(f"\n模拟处理主机: {host}")
        logging.info(f"    - 在主机 {host} 上模拟执行 '停止应用': '{stop_cmd}'")

        backup_exclude_options_list = []
        
        # --- 修正: 健壮处理 global_exclude_logs_param ---
        global_exclude_items = []
        if isinstance(global_exclude_logs_param, list):
            global_exclude_items = global_exclude_logs_param
            logging.debug(f"DEBUG: global_exclude_items (list): {global_exclude_items}")
        elif isinstance(global_exclude_logs_param, str):
            global_exclude_items = [f.strip() for f in global_exclude_logs_param.split(',') if f.strip()]
            logging.debug(f"DEBUG: global_exclude_items (str processed to list): {global_exclude_items}")
        else:
            logging.debug(f"DEBUG: global_exclude_logs_param is neither list nor str: {type(global_exclude_logs_param)}")
        
        for f_stripped in global_exclude_items:
            backup_exclude_options_list.append(f"--exclude={f_stripped}")
        # --- 修正结束 ---

        if app_log_dir:
            app_log_dir_stripped = app_log_dir.strip()
            if app_log_dir_stripped:
                backup_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/")
                backup_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/*")

        simulated_exclude_str = " ".join(backup_exclude_options_list)
        logging.info(f"    - 模拟rsync 备份远程代码到本地: 从 '{host}:{web_path}/' 到 '本地: {BACKUP_DIR}/{app_name}/{current_date}/{host}/{app_name}' {simulated_exclude_str}")


        local_update_source_path = os.path.join("update", app_name) + os.sep
        logging.info(f"    - 假设本地更新源路径为: {local_update_source_path}")

        update_exclude_options_list = []
        if app_log_dir:
            app_log_dir_stripped = app_log_dir.strip()
            if app_log_dir_stripped:
                update_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/")
                update_exclude_options_list.append(f"--exclude={app_log_dir_stripped}/*")
        
        # --- 修正: 健壮处理 app_retained_config_file_param ---
        retained_config_items = []
        if isinstance(app_retained_config_file_param, list):
            retained_config_items = app_retained_config_file_param
            logging.debug(f"DEBUG: retained_config_items (list): {retained_config_items}")
        elif isinstance(app_retained_config_file_param, str):
            retained_config_items = [f.strip() for f in app_retained_config_file_param.split(',') if f.strip()]
            logging.debug(f"DEBUG: retained_config_items (str processed to list): {retained_config_items}")
        else:
            logging.debug(f"DEBUG: app_retained_config_file_param is neither list nor str: {type(app_retained_config_file_param)}")
        
        for f_stripped in retained_config_items:
            update_exclude_options_list.append(f"--exclude={f_stripped}")
        # --- 修正结束 ---

        if middle_type == "tomcat" and group_name == "update" and master_exclusive_files:
            # --- 新增调试日志：打印 master_exclusive_files 的内容和类型 ---
            logging.debug(f"DEBUG: master_exclusive_files content: {master_exclusive_files}")
            for i, item in enumerate(master_exclusive_files):
                logging.debug(f"DEBUG: master_exclusive_files[{i}] type: {type(item)}, value: {item}")
            # --- 调试日志结束 ---
            for f in master_exclusive_files: # master_exclusive_files 已经是列表
                # 确保 f 是字符串才调用 strip()
                f_stripped = f.strip() if isinstance(f, str) else str(f)
                if f_stripped:
                    update_exclude_options_list.append(f"--exclude={f_stripped}")
            logging.info(f"    - Tomcat Update群组，将额外排除文件: {', '.join([str(x) for x in master_exclusive_files])}") # 确保join的是字符串

        simulated_update_exclude_str = " ".join(update_exclude_options_list) + " --delete"
        logging.info(f"    - 模拟rsync 复制更新代码 (带 --delete 选项): 从 '{local_update_source_path}' 到 '10.2.0.173:{web_path}/' {simulated_update_exclude_str}")

        logging.debug(f"    - 模拟验证远程目录 {web_path} 内容 (rsync后):")
        logging.debug(f"      模拟远程目录内容: (此处应显示实际ls -la输出，模拟中省略)")

        logging.info(f"    - 在主机 10.2.0.173 上模拟执行 '更新文件所属用户和用户组': 'chown -R egova:egova /egova/web/eUrbanMIS'")
        logging.info(f"    - 在主机 10.2.0.173 上模拟执行 '启动应用': 'systemctl start tomcat-MIS'")
        logging.info(f"    - 模拟检查 eUrbanMIS (10.2.0.173:8081/eUrbanMIS/main.htm) 是否可用，等待 1 分钟...")
        time.sleep(5) # 模拟等待时间
        logging.info(f"    - 模拟更新和启动验证通过。")


def simulate_static_partial_update(app_name, static_update_path, groups_to_update_static, current_date, selected_app):
    '''
    模拟处理静态页面部分更新逻辑。
    '''
    logging.info(f"\n--- 模拟处理 {app_name} 的静态页面部分更新 ---")
    
    local_update_source_base = os.path.join("update", app_name)
    local_static_source_path = os.path.join(local_update_source_base, static_update_path)

    if not os.path.exists(local_static_source_path):
        logging.error(f"错误: 本地静态更新源路径 '{local_static_source_path}' 不存在。模拟无法继续。")
        return

    for group_name in groups_to_update_static:
        group_hosts = selected_app.get(group_name, [])
        if not group_hosts:
            logging.warning(f"警告: {app_name} 的 {group_name} 群组没有配置主机。跳过静态部分更新模拟。")
            continue

        for host_info in group_hosts:
            host = host_info['host']
            web_path = host_info['web_path']
            file_user = host_info.get('user', 'root')
            file_group = host_info.get('group', 'root')

            remote_base_path = "" # 远程目标路径的根
            remote_static_target_path = "" # 远程静态文件最终目标路径
            chown_target_path = "" # chown命令的目标路径

            if selected_app['middle_type'] == 'jar' and group_name in ['master', 'update']:
                remote_base_path = os.path.join(web_path, host_info.get('static_page_path', ''))
                remote_static_target_path = os.path.join(remote_base_path, static_update_path)
                chown_target_path = remote_base_path
            elif group_name == 'static_page_group':
                # web_path 已经是静态文件服务器上该应用的根路径 (例如: /egova/web/nginx_deploy/eUrbanMIS)
                remote_base_path = web_path
                remote_static_target_path = os.path.join(remote_base_path, static_update_path)
                chown_target_path = remote_base_path
            else: # Tomcat master/update groups
                remote_base_path = web_path # web_path 已经是应用的根目录 (例如: /egova/web/eUrbanMIS)
                remote_static_target_path = os.path.join(remote_base_path, static_update_path)
                chown_target_path = remote_base_path

            logging.info(f"\n模拟处理主机: {host} ({group_name} 群组)")
            # 调整模拟备份路径
            if group_name == 'static_page_group':
                local_backup_path_with_app = os.path.join(BACKUP_DIR, app_name, current_date, host, "nginx_deploy", static_update_path)
            else: # master and update groups
                local_backup_path_with_app = os.path.join(BACKUP_DIR, app_name, current_date, host, app_name, static_update_path)

            logging.info(f"    - 模拟rsync 备份远程静态页面路径 '{remote_static_target_path}/' 到本地: {local_backup_path_with_app}")
            logging.info(f"    - 模拟rsync 复制本地静态页面路径 '{local_static_source_path}/' 到远程: {remote_static_target_path}/ (带 --delete)")
            logging.info(f"    - 模拟更新文件所属用户和用户组: chown -R {file_user}:{file_group} {chown_target_path}")
            logging.info(f"    - {app_name} 在 {host} 上静态页面部分更新模拟成功！")

def simulate_static_full_update_tomcat(app_name, static_page_group_hosts, current_date, selected_app):
    '''
    模拟处理Tomcat应用的静态页面全量更新逻辑。
    '''
    logging.info(f"\n--- 模拟处理 {app_name} 的静态页面全量更新 (Tomcat) ---")

    local_app_update_dir = os.path.join("update", app_name)
    local_nginx_deploy_dir = os.path.join(local_app_update_dir, "nginx_deploy", app_name)

    logging.info(f"    - Performing static file extraction for {app_name} locally (simulated)...")
    # Simulate creation of the output directory
    os.makedirs(local_nginx_deploy_dir, exist_ok=True)
    logging.info(f"    - Simulated local static file extraction completed successfully. Output directory: {local_nginx_deploy_dir}")

    if not static_page_group_hosts:
        logging.warning("警告: 未配置静态页面群组。无法执行静态页面全量更新模拟。")
        return

    for host_info in static_page_group_hosts:
        host = host_info['host']
        web_path = host_info['web_path']
        file_user = host_info.get('user', 'nginx')
        file_group = host_info.get('group', 'nginx')

        # 远程静态文件根目录，例如 /egova/web/nginx_deploy/eUrbanMIS
        # web_path 已经是静态文件服务器上该应用的根路径 (例如: /egova/web/nginx_deploy/eUrbanMIS)
        # 修正: 移除 web_path 末尾的斜杠，避免双斜杠
        remote_static_app_root = web_path.rstrip('/')

        logging.info(f"\n模拟处理静态页面服务器: {host}")
        logging.info(f"    - 模拟rsync 备份远程静态页面根目录: {remote_static_app_root}/ 到本地: {BACKUP_DIR}/{app_name}/{current_date}/{host}/nginx_deploy/static_full_backup")
        logging.info(f"    - 模拟rsync 推送本地提取的全量静态文件 '{local_nginx_deploy_dir}/' 到远程: {remote_static_app_root}/ (带 --delete)")
        logging.info(f"    - 模拟更新文件所属用户和用户组: chown -R {file_user}:{file_group} {remote_static_app_root}")
    logging.info(f"    - {app_name} 在 {host} 上静态页面全量更新模拟成功！")


def simulate_static_update_jar(app_name, static_update_source_path_local, groups_to_update_jar_static, current_date, selected_app):
    '''
    模拟处理JAR类应用的静态页面更新逻辑。
    '''
    logging.info(f"\n--- 模拟处理 {app_name} 的静态页面更新 (JAR) ---")

    if not os.path.exists(static_update_source_path_local):
        logging.error(f"错误: 本地静态更新源路径 '{local_static_source_path}' 不存在。模拟无法继续。")
        return

    for group_name in groups_to_update_jar_static:
        group_hosts = selected_app.get(group_name, [])
        if not group_hosts:
            logging.warning(f"警告: {app_name} 的 {group_name} 群组没有配置主机。跳过JAR静态更新模拟。")
            continue

        for host_info in group_hosts:
            host = host_info['host']
            web_path = host_info['web_path']
            file_user = host_info.get('user', 'root')
            file_group = host_info.get('group', 'root')

            remote_destination_path = ""
            if group_name == 'static_page_group':
                # 对于静态页面服务器，目标是web_path (已包含应用名)
                # 修正: 移除 web_path 末尾的斜杠，避免双斜杠
                remote_destination_path = web_path.rstrip('/')
                file_user = host_info.get('user', 'nginx')
                file_group = host_info.get('group', 'nginx')
            else:
                # 对于Master/Update群组，目标是web_path + static_page_path
                static_page_path_on_host = host_info.get('static_page_path', '')
                if not static_page_path_on_host:
                    logging.warning(f"警告: 主机 {host} ({group_name} 群组) 未配置 'static_page_path'。跳过此主机的JAR静态更新模拟。")
                    continue
                remote_destination_path = os.path.join(web_path, static_page_path_on_host)

            logging.info(f"\n模拟处理主机: {host} ({group_name} 群组)")
            # 调整模拟备份路径
            logging.info(f"    - 模拟rsync 备份远程静态页面路径 '{remote_destination_path}/' 到本地: {BACKUP_DIR}/{app_name}/{current_date}/{host}/nginx_deploy/static_jar_backup")
            logging.info(f"    - 模拟rsync 复制本地静态文件 '{static_update_source_path_local}/' 到远程: {remote_destination_path}/ (带 --delete)")
            logging.info(f"    - 模拟更新文件所属用户和用户组: chown -R {file_user}:{file_group} {remote_destination_path}")
            logging.info(f"    - {app_name} 在 {host} 上JAR静态页面更新模拟成功！")


def run_update_process(config):
    '''
    执行应用更新过程。
    参数:
        config (dict): 从config.yaml加载的配置数据。
    '''
    setup_logging() # <--- 新增：在主更新流程开始时配置日志

    if not config:
        logging.error("配置数据为空，无法执行更新过程。请检查 config.yaml 文件。")
        sys.stdout.flush() # Use sys.stdout.flush() directly
        return

    logging.debug(f"Loaded config: {config}") # 打印加载的整个配置，只进入日志文件

    webs = config.get("webs", [])
    logging.debug(f"Applications (webs) in config: {webs}") # 打印应用列表，只进入日志文件

    if not webs:
        logging.info("配置文件中没有找到任何应用配置。")
        sys.stdout.flush() # Use sys.stdout.flush() directly
        return

    logging.info("\n--- 选择要更新的应用 ---")
    for i, app in enumerate(webs):
        logging.info(f"{i+1}. {app['web']} ({app['middle_type']})")
    sys.stdout.flush() # <--- 新增：强制刷新，确保应用列表立即显示

    try:
        choice = int(get_input("请输入要更新的应用编号")) - 1
        if not (0 <= choice < len(webs)):
            logging.warning("无效的应用编号。")
            return
    except ValueError:
        logging.warning("请输入有效的数字。")
        return

    selected_app = webs[choice]
    app_name = selected_app['web']
    middle_type = selected_app['middle_type']
    
    master_exclusive_files = selected_app.get('master_exclusive_files', [])
    if isinstance(master_exclusive_files, str): # Ensure it's a list for consistency
        master_exclusive_files = [f.strip() for f in master_exclusive_files.split(',') if f.strip()]
    
    app_log_dir = selected_app.get('log_dir', '').strip()
    app_retained_config_file_raw = selected_app.get('retained_config_file', '')
    global_exclude_logs_raw = config.get('global_exclude_logs', '')
    static_page_group_hosts = selected_app.get('static_page_group', [])

    logging.info(f"\n--- 开始更新应用: {app_name} ---")

    current_datetime_str = datetime.datetime.now().strftime("%Y%m%d%H")

    # Track if master/update groups have been processed for Tomcat full static update precondition
    # These flags are reset on each run_update_process call, which is why the warning persists.
    # We will make the check advisory.
    master_updated = False 
    update_updated = False

    while True:
        logging.info(f"\n--- 选择要更新的群组 ({app_name}) ---")
        logging.info("1. Master 群组")
        logging.info("2. Update 群组")
        logging.info("3. 所有应用群组 (Master 和 Update)")
        
        if middle_type == 'tomcat':
            # 修改静态页面部分更新的提示信息
            logging.info("4. 静态页面部分更新 (Tomcat) - 请输入相对于应用部署根目录的路径 (例如: view/index.html 或 view/css)")
            logging.info("5. 静态页面全量更新 (Tomcat)")
            logging.info("6. 返回主菜单")
            max_choice = 6
        elif middle_type == 'jar':
            logging.info("4. 静态页面更新 (JAR)")
            logging.info("5. 返回主菜单")
            max_choice = 5
        else:
            logging.info("4. 返回主菜单")
            max_choice = 4

        group_choice = get_input(f"请输入您的选择 (1-{max_choice})", str(max_choice))

        groups_to_update = []
        groups_to_update_static_pages = [] # For partial/full static updates

        if group_choice == '1':
            groups_to_update = ["master"]
        elif group_choice == '2':
            groups_to_update = ["update"]
        elif group_choice == '3':
            groups_to_update = ["master", "update"]
        elif (middle_type == 'tomcat' and group_choice == '4'): # Tomcat Static Partial Update
            
            # For partial update, update all relevant groups
            groups_to_update_static_pages = ["master", "update", "static_page_group"]
            
            # Check if any hosts exist in the selected static groups
            has_hosts_to_update = False
            for g_name in groups_to_update_static_pages:
                if selected_app.get(g_name):
                    has_hosts_to_update = True
                    break
            
            if not has_hosts_to_update:
                logging.warning("警告: 未配置任何应用群组或静态页面群组的主机。无法执行静态页面部分更新。")
                continue

            # 修改静态更新路径的提示信息
            static_update_path = get_input("请输入应用内的静态更新路径 (此路径相对于应用部署根目录，例如: view/index.html 或 view/css)", "").strip()
            if not static_update_path:
                logging.warning("静态更新路径不能为空。")
                continue
            
            # Simulate static partial update
            simulate_static_partial_update(app_name, static_update_path, groups_to_update_static_pages, current_datetime_str, selected_app)

            confirm = get_input(f"是否要继续执行静态页面部分更新操作? (y/n)", "n").lower()
            if confirm == 'y':
                process_static_partial_update(app_name, static_update_path, groups_to_update_static_pages, current_datetime_str, selected_app)
                logging.info(f"\n--- 静态页面部分更新过程完成 ---")
            else:
                logging.info(f"用户取消了静态页面部分更新操作。")
            continue # Go back to main update menu

        elif middle_type == 'tomcat' and group_choice == '5': # Tomcat Static Full Update
            # Removed the 'continue' statement to make this warning advisory
            if (selected_app.get('master') and not master_updated) or \
               (selected_app.get('update') and not update_updated):
                logging.warning("警告: 执行静态页面全量更新前，请先完成Master和Update群组的更新（或确保其为空）。")

            if not static_page_group_hosts:
                logging.warning("警告: 未配置静态页面群组。无法执行静态页面全量更新。")
                continue

            # Removed prompt for pack_script_path, now handled internally
            # pack_script_path = get_input("请输入静态文件提取脚本的本地路径 (例如: 220908090120_pack_gis_for_nginx.sh 或 pack_for_nginx_for_20230101.sh)", "").strip()
            # if not pack_script_path:
            #     logging.warning("静态文件提取脚本路径不能为空。")
            #     continue
            
            # # Validate script existence (no longer needed as scripts are integrated)
            # if not os.path.exists(pack_script_path):
            #     logging.error(f"错误: 静态文件提取脚本 '{pack_script_path}' 不存在。请检查路径。")
            #     continue

            # Simulate static full update (no pack_script_path needed)
            simulate_static_full_update_tomcat(app_name, static_page_group_hosts, current_datetime_str, selected_app)

            confirm = get_input(f"是否要继续执行静态页面全量更新操作? (y/n)", "n").lower()
            if confirm == 'y':
                # Call process_static_full_update_tomcat without pack_script_path
                process_static_full_update_tomcat(app_name, static_page_group_hosts, current_datetime_str, selected_app)
                logging.info(f"\n--- 静态页面全量更新过程完成 ---")
            else:
                logging.info(f"用户取消了静态页面全量更新操作。")
            continue # Go back to main update menu

        elif middle_type == 'jar' and group_choice == '4': # JAR Static Update
            groups_to_update_jar_static = ["master", "update", "static_page_group"]

            has_hosts_to_update = False
            for g_name in groups_to_update_jar_static:
                if selected_app.get(g_name):
                    has_hosts_to_update = True
                    break
            
            if not has_hosts_to_update:
                logging.warning("警告: 未配置任何应用群组或静态页面群组的主机。无法执行JAR静态页面更新。")
                continue

            static_update_source_path_local = get_input("请输入本地update目录内对应应用包内的静态文件总路径 (例如: update/eUrbanMIS/nginx_deploy/eUrbanMIS)", "").strip()
            if not static_update_source_path_local:
                logging.warning("本地静态文件总路径不能为空。")
                continue

            if not os.path.exists(static_update_source_path_local):
                logging.error(f"错误: 本地静态更新源路径 '{static_update_source_path_local}' 不存在。请检查路径是否正确。")
                continue

            # Simulate JAR static update
            simulate_static_update_jar(app_name, static_update_source_path_local, groups_to_update_jar_static, current_datetime_str, selected_app)

            confirm = get_input(f"是否要继续执行JAR静态页面更新操作? (y/n)", "n").lower()
            if confirm == 'y':
                process_static_update_jar(app_name, static_update_source_path_local, groups_to_update_jar_static, current_datetime_str, selected_app)
                logging.info(f"\n--- JAR静态页面更新过程完成 ---")
            else:
                logging.info(f"用户取消了JAR静态页面更新操作。")
            continue # Go back to main update menu

        elif (middle_type == 'tomcat' and group_choice == '6') or \
             (middle_type == 'jar' and group_choice == '5') or \
             (middle_type not in ['tomcat', 'jar'] and group_choice == '4'): # Return to main menu
            logging.info("返回主菜单。")
            break
        else:
            logging.warning("无效的选择，请重新输入。")
            continue

        # Process standard master/update groups (this block is executed if group_choice was 1, 2, or 3)
        for group_name in groups_to_update:
            group_hosts = selected_app.get(group_name, [])
            if not group_hosts:
                logging.warning(f"警告: {app_name} 的 {group_name} 群组没有配置主机。跳过。")
                if group_name == "master":
                    master_updated = True
                elif group_name == "update":
                    update_updated = True
                continue

            # Simulate execution
            simulate_group_update(app_name, middle_type, master_exclusive_files, global_exclude_logs_raw, app_log_dir, app_retained_config_file_raw, current_datetime_str, group_name, group_hosts)
            logging.info(f"\n--- {group_name} 群组模拟执行完成 ---")

            confirm = get_input(f"是否要继续执行 {group_name} 群组的实际更新操作? (y/n)", "n").lower()
            if confirm == 'y':
                process_group_update(app_name, middle_type, master_exclusive_files, global_exclude_logs_raw, app_log_dir, app_retained_config_file_raw, current_datetime_str, group_name, group_hosts)
                logging.info(f"\n--- {group_name} 群组实际更新过程完成 ---")
                if group_name == "master":
                    master_updated = True
                elif group_name == "update":
                    update_updated = True
            else:
                logging.info(f"用户取消了 {group_name} 群组的实际更新操作。")
                # If user cancels, mark as not updated for precondition
                if group_name == "master":
                    master_updated = False
                elif group_name == "update":
                    update_updated = False

        # After processing standard groups, check if user wants to continue updating other groups or re-select
        if group_choice in ['1', '2', '3']:
            continue_updating = get_input("\n是否继续更新其他群组或重新选择? (y/n)", "n").lower()
            if continue_updating != 'y':
                logging.info(f"\n--- 应用 {app_name} 更新过程完成 ---")
                break


if __name__ == "__main__":
    # Removed setup_logging() from here, as it's now called in run_update_process()
    logging.info("欢迎使用应用更新工具 - 更新执行器！")
    config = load_config()
    if config:
        run_update_process(config)
