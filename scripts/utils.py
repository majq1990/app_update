import yaml
import os
import time
import subprocess
import requests
import logging
import datetime
import sys # Import sys module here

# 定义配置文件路径
CONFIG_FILE = "config/config.yaml"
# 定义备份目录
BACKUP_DIR = "backups"
# 定义日志目录
LOG_DIR = "logs"

def setup_logging():
    '''
    配置日志功能，将日志输出到控制台和每日日志文件。
    '''
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file_name = datetime.datetime.now().strftime("app_updater_%Y%m%d.log")
    log_file_path = os.path.join(LOG_DIR, log_file_name)

    # 获取根日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) # 设置整体日志级别为DEBUG

    # 清除现有处理器，防止重复日志
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

    # 控制台处理器 (INFO级别)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 文件处理器 (DEBUG级别)
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    logging.info(f"日志已配置。日志文件: {log_file_path}")


def load_config():
    '''
    从config.yaml文件加载配置数据。
    返回:
        dict: 配置数据，如果文件不存在或加载失败则返回None。
    '''
    if not os.path.exists(CONFIG_FILE):
        logging.warning(f"配置文件 '{CONFIG_FILE}' 不存在。请先生成配置。")
        return None
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        logging.info(f"配置文件 '{CONFIG_FILE}' 已成功加载。")

        # --- NEW: Ensure specific fields are lists of strings after loading ---
        if config_data and 'webs' in config_data:
            for app in config_data['webs']:
                # Convert master_exclusive_files to list if it's a string
                if 'master_exclusive_files' in app:
                    if isinstance(app['master_exclusive_files'], str):
                        app['master_exclusive_files'] = [f.strip() for f in app['master_exclusive_files'].split(',') if f.strip()]
                    elif not isinstance(app['master_exclusive_files'], list):
                        app['master_exclusive_files'] = [] # Ensure it's a list if not string or list
                else:
                    app['master_exclusive_files'] = [] # Default to empty list if not present

                # Convert retained_config_file to list if it's a string
                if 'retained_config_file' in app:
                    if isinstance(app['retained_config_file'], str):
                        app['retained_config_file'] = [f.strip() for f in app['retained_config_file'].split(',') if f.strip()]
                    elif not isinstance(app['retained_config_file'], list):
                        app['retained_config_file'] = [] # Ensure it's a list if not string or list
                else:
                    app['retained_config_file'] = [] # Default to empty list if not present
        # --- END NEW ---

        return config_data
    except Exception as e:
        logging.error(f"加载配置文件时发生错误: {e}")
        return None

def get_input(prompt, default=None):
    '''
    获取用户输入，支持默认值。
    参数:
        prompt (str): 提示信息。
        default (str): 默认值。
    返回:
        str: 用户输入或默认值。
    '''
    # Force flush stdout before taking input to ensure prompt is visible
    sys.stdout.flush()
    if default is not None:
        return input(f"{prompt} (默认: {default}): ") or str(default)
    else:
        return input(f"{prompt}: ")

def execute_remote_command(host, command, action_description):
    '''
    在远程主机上执行命令。
    参数:
        host (str): 远程主机IP。
        command (str): 要执行的命令字符串。
        action_description (str): 命令的描述，用于日志。
    返回:
        bool: 命令是否成功执行。
    '''
    full_command = ['ssh', host, command]
    logging.info(f"    - 在主机 {host} 上执行 '{action_description}': '{command}'")
    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=True, timeout=60)
        logging.debug(f"        标准输出:\n{result.stdout.strip()}")
        if result.stderr:
            # Changed from logging.warning to logging.debug
            logging.debug(f"        标准错误:\n{result.stderr.strip()}")
        logging.info(f"    - 命令 '{action_description}' 在 {host} 上执行成功。")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"        错误: 命令 '{action_description}' 在 {host} 上执行失败: {e}")
        logging.error(f"        标准输出:\n{e.stdout.strip()}")
        logging.error(f"        标准错误:\n{e.stderr.strip()}")
        return False
    except Exception as e:
        logging.error(f"执行远程命令时发生未知错误: {e}")
        return False

def execute_rsync(source, destination, host, action_description, exclude_options=None):
    '''
    执行rsync命令进行文件同步。
    参数:
        source (str): 源路径 (本地或远程)。
        destination (str): 目标路径 (本地或远程)。
        host (str): 远程主机IP (如果源或目标是远程的)。
        action_description (str): rsync操作的描述，用于日志。
        exclude_options (list): rsync的排除选项列表 (例如: ["--exclude=logs/", "--exclude=*.log"])。
    返回:
        bool: rsync命令是否成功执行。
    '''
    # 添加 --quiet 选项以抑制详细的传输输出到控制台
    command = ['rsync', '-avz', '--quiet'] # -a: archive mode, -v: verbose, -z: compress, --quiet: suppress non-error messages
    if exclude_options:
        command.extend(exclude_options)

    # Determine if source or destination is remote
    is_source_remote = ":" in source and not os.path.isabs(source) # Simple check for remote path
    is_destination_remote = ":" in destination and not os.path.isabs(destination)

    if is_source_remote:
        command.append(f"{source}")
        command.append(destination)
    elif is_destination_remote:
        command.append(source)
        command.append(f"{destination}")
    else: # Local to local rsync (shouldn't happen in this context, but for completeness)
        command.append(source)
        command.append(destination)

    logging.info(f"    - 执行rsync {action_description}: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        # 详细的rsync输出（包括文件列表、进度等）记录为DEBUG
        logging.debug(f"        rsync 标准输出:\n{result.stdout.strip()}")
        if result.stderr:
            # rsync有时会将非错误信息（如“sending incremental file list”）输出到stderr
            logging.debug(f"        rsync 标准错误:\n{result.stderr.strip()}")
        logging.info(f"    - rsync '{action_description}' 执行成功。")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"        错误: rsync '{action_description}' 执行失败: {e}")
        logging.error(f"        标准输出:\n{e.stdout.strip()}")
        logging.error(f"        标准错误:\n{e.stderr.strip()}")
        return False
    except FileNotFoundError:
        logging.error("错误: 'rsync' 命令未找到。请确保已安装rsync。")
        return False
    except Exception as e:
        logging.error(f"执行rsync时发生未知错误: {e}")
        return False


def check_uri_availability(uri, host, port, app_name, middle_type, timeout_minutes=1):
    '''
    检查URI是否可用。
    参数:
        uri (str): 要检查的URI路径 (例如: /eUrbanMIS/main.htm)。
        host (str): 主机IP。
        port (int): 服务端口。
        app_name (str): 应用名称，用于日志。
        middle_type (str): 中间件类型，用于特定逻辑（例如tomcat的额外等待）。
        timeout_minutes (int): 超时时间（分钟）。
    返回:
        bool: URI是否可用。
    '''
    if not uri:
        logging.warning(f"警告: 应用 '{app_name}' 未配置URI检查路径。跳过URI可用性检查。")
        return True

    full_url = f"http://{host}:{port}{uri}"
    logging.info(f"    - 正在检查 {app_name} ({full_url}) 是否可用，初始等待 {timeout_minutes} 分钟...")

    start_time = time.time()
    while time.time() - start_time < timeout_minutes * 60:
        try:
            response = requests.get(full_url, timeout=10) # 每次请求超时10秒
            if response.status_code == 200:
                logging.info(f"    - {app_name} 在 {host} 上检查URI成功。服务已响应。")
                return True
            else:
                logging.debug(f"      URI {full_url} 返回状态码: {response.status_code}. Retrying...")
        except requests.exceptions.ConnectionError:
            logging.debug(f"      无法连接到 {full_url}. Retrying...")
        except requests.exceptions.Timeout:
            logging.debug(f"      连接到 {full_url} 超时. Retrying...")
        except Exception as e:
            logging.debug(f"      检查URI时发生未知错误: {e}. Retrying...")
        time.sleep(10) # 每次尝试之间等待10秒

    logging.error(f"    - 错误: {app_name} 在 {host} 上URI检查失败。{full_url} 在 {timeout_minutes} 分钟内未响应。")
    return False

def setup_passwordless_ssh(host, user, password, port):
    '''
    设置SSH免密登录。
    参数:
        host (str): 远程主机IP。
        user (str): SSH用户名。
        password (str): SSH密码。
        port (int): SSH端口。
    返回:
        bool: SSH免密设置是否成功。
    '''
    logging.info(f"正在尝试为 {user}@{host}:{port} 设置SSH免密登录...")

    # 1. 检查本地是否存在SSH密钥对，如果不存在则生成
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key_path = os.path.join(ssh_dir, "id_rsa")
    public_key_path = os.path.join(ssh_dir, "id_rsa.pub")

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        logging.info("未找到SSH密钥对，正在生成...")
        try:
            # -t rsa: 指定RSA算法, -b 4096: 4096位密钥, -N "": 无密码, -f: 指定文件路径
            subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-N', '', '-f', private_key_path], check=True, capture_output=True, text=True)
            logging.info("SSH密钥对生成成功。")
        except subprocess.CalledProcessError as e:
            logging.error(f"错误: SSH密钥对生成失败: {e.stderr.strip()}")
            return False
        except Exception as e:
            logging.error(f"生成公钥 (ssh-keygen) 时发生未知错误: {e}")
            return False

    # 使用 sshpass 和 ssh-copy-id 进行自动化
    # 注意: 在生产环境中直接在命令行中使用sshpass传递密码通常不推荐，存在安全风险。
    # 对于自动化部署，更推荐使用SSH Agent Forwarding或Ansible Vault等安全方式。
    command = [
        'sshpass', '-p', password,
        'ssh-copy-id',
        '-o', 'StrictHostKeyChecking=no', # 首次连接时避免主机密钥提示
        '-p', str(port),
        f'{user}@{host}'
    ]

    try:
        # 打印命令时隐藏密码
        logging.info(f"执行命令: {' '.join(command[:-3])} -p {port} {user}@{host}")
        process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60) # 增加超时
        logging.info("SSH免密设置成功！")
        logging.debug(f"标准输出:\n{process.stdout}")
        if process.stderr:
            logging.warning(f"标准错误:\n{process.stderr}")
        return True
    except FileNotFoundError:
        logging.error("错误: 'sshpass' 或 'ssh-copy-id' 命令未找到。请确保它们已安装并添加到PATH中。")
        logging.info("在Debian/Ubuntu上: apt-get install sshpass openssh-client")
        logging.info("在CentOS/RHEL上: yum install sshpass openssh-clients")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"错误: SSH免密设置失败: {e.stderr.strip()}")
        logging.debug(f"标准输出:\n{e.stdout.strip()}")
        logging.debug(f"标准错误:\n{e.stderr.strip()}")
        return False
    except Exception as e:
        logging.error(f"设置SSH免密登录时发生未知错误: {e}")
        return False

