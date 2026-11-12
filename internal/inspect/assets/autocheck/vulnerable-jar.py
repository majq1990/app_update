#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞jar包检查脚本
检查系统中是否存在已知漏洞的第三方jar包
基于原始scan_vulnerable_jar.sh脚本逻辑重写
"""

import os
import re
import json
import subprocess
import argparse
import sys
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

# 漏洞jar包最低版本列表
VULNERABLE_JARS = {
    "fastjson": "1.2.83",
    "commons-fileupload": "1.5",
    "commons-text": "1.10.0",
    "axis": "1.4",
    "axis-saaj": "1.4",
    "commons-collections": "3.2.2",
    "commons-collections4": "4.1",
    "log4j-web": "2.17.1",
    "log4j-api": "2.17.1",
    "log4j-jcl": "2.17.1",
    "log4j-core": "2.17.1",
    "log4j-slf4j-impl": "2.17.1",
    "jackson-databind": "2.12.1",  # 升级为2.12.4
    "postgresql": "42.4.1",
    "h2": "2.2.220",
    "xstream": "1.4.20",
    "rocketmq-client": "4.3.0",
    "rocketmq-common": "4.3.0",
    "rocketmq-logging": "4.3.0",
    "rocketmq-remoting": "4.3.0",
    "poi-ooxml": "4.1.2",
    "poi-ooxml-schemas": "4.1.2",
    "poi-scratchpad": "4.1.2",
    "mysql-connector-java": "8.0.30"  # 仅扫描
}

# 仅扫描不做自动替换的jar
ONLY_SCAN_JARS = {
    "mysql-connector-java": "cetus字符集可能存在不兼容问题,需先升级cetus",
    "jackson-databind": "[335925]疑似2.9版本的jackson无法直接升级2.12,联系研发更新相关代码",
    "poi-ooxml": "poi升级需研发确认是否同步升级代码",
    "poi-ooxml-schemas": "poi升级需研发确认是否同步升级代码",
    "poi-scratchpad": "poi升级需研发确认是否同步升级代码",
    "xstream": "xstream升级需研发确认是否同步升级代码"
}

# 额外扫描的目录
EXTRA_SCAN_DIRS = [
    "/egova/web",
    "/egova/apps/",
    "/egova/egova_apps/",
    "/egova/ZTnew",
    "/egova_apps",
    "/egova_docker",
    "/egova/egova_docker",
    "/egova/datatransfer",
    "/egova/auth-center"
]

class VulnerableJarScanner:
    def __init__(self):
        self.results = {
            "vulnerable_jars": [],
            "scan_summary": {
                "total_vulnerabilities": 0,
                "vulnerable_jar_files": 0,
                "vulnerable_fatjars": 0,
                "scan_directories": [],
                "scan_containers": []
            }
        }

    def parse_version(self, version_str: str) -> List[int]:
        """解析版本号为数字列表"""
        # 移除常见的版本修饰符
        clean_version = re.sub(r'[^0-9.]', '', version_str)
        return [int(x) for x in clean_version.split('.') if x.isdigit()]

    def compare_versions(self, version1: str, version2: str) -> int:
        """比较版本号，返回 -1, 0, 1"""
        v1_parts = self.parse_version(version1)
        v2_parts = self.parse_version(version2)

        # 补齐版本号长度
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))

        for v1, v2 in zip(v1_parts, v2_parts):
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
        return 0

    def extract_jar_info(self, jar_filename: str) -> Tuple[str, str]:
        """从jar文件名中提取jar名称和版本号"""
        # 匹配格式: name-version.jar
        match = re.match(r'^([^-]+)-(.+)\.jar$', jar_filename, re.IGNORECASE)
        if match:
            jar_name = match.group(1)
            jar_version = match.group(2)
            return jar_name, jar_version
        return jar_filename, ""

    def check_jar_vulnerability(self, jar_path: str) -> Optional[Dict]:
        """检查单个jar文件是否存在漏洞"""
        jar_filename = os.path.basename(jar_path)
        jar_name, jar_version = self.extract_jar_info(jar_filename)

        # 检查是否在漏洞列表中
        for vuln_jar, min_version in VULNERABLE_JARS.items():
            if jar_name.lower().startswith(vuln_jar.lower()) or jar_filename.lower().startswith(vuln_jar.lower()):
                if jar_version and self.compare_versions(jar_version, min_version) < 0:
                    # 检查是否仅扫描
                    only_scan_reason = ONLY_SCAN_JARS.get(vuln_jar, "")

                    return {
                        "jar_path": jar_path,
                        "jar_filename": jar_filename,
                        "jar_name": jar_name,
                        "current_version": jar_version,
                        "minimum_safe_version": min_version,
                        "vulnerability_type": vuln_jar,
                        "only_scan": vuln_jar in ONLY_SCAN_JARS,
                        "only_scan_reason": only_scan_reason
                    }
        return None

    def find_java_processes(self) -> List[Dict]:
        """查找Java进程"""
        processes = []
        try:
            ps_output = subprocess.check_output(['ps', 'aux'], stderr=subprocess.DEVNULL).decode('utf-8')

            for line in ps_output.split('\n'):
                if 'java' in line and 'grep' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[1]
                        cmdline = ' '.join(parts[10:])

                        # 提取-jar参数
                        jar_match = re.search(r'-jar\s+(\S+\.jar)', cmdline)
                        jar_file = jar_match.group(1) if jar_match else None

                        # 提取-cp/-classpath参数
                        cp_match = re.search(r'-(?:cp|classpath)\s+([^\s]+)', cmdline)
                        classpath = cp_match.group(1) if cp_match else None

                        processes.append({
                            "pid": pid,
                            "cmdline": cmdline,
                            "jar_file": jar_file,
                            "classpath": classpath
                        })
        except subprocess.CalledProcessError:
            pass
        return processes

    def check_fatjar(self, jar_path: str) -> List[Dict]:
        """检查fatjar中是否包含漏洞jar包"""
        vulnerabilities = []

        try:
            # 检查jar命令是否可用
            subprocess.run(['jar', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

            # 列出jar包内容
            jar_output = subprocess.check_output(['jar', '-tf', jar_path], stderr=subprocess.DEVNULL).decode('utf-8')

            for line in jar_output.split('\n'):
                if line.endswith('.jar'):
                    inner_jar = os.path.basename(line)
                    vuln_info = self.check_jar_vulnerability(inner_jar)
                    if vuln_info:
                        vuln_info.update({
                            "container_type": "fatjar",
                            "container_path": jar_path,
                            "inner_jar_path": line
                        })
                        vulnerabilities.append(vuln_info)

        except (subprocess.CalledProcessError, FileNotFoundError):
            # jar命令不可用时跳过fatjar检查
            pass

        return vulnerabilities

    def check_directory(self, directory: str) -> List[Dict]:
        """检查目录中的jar文件"""
        vulnerabilities = []

        if not os.path.exists(directory) or not os.path.isdir(directory):
            return vulnerabilities

        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith('.jar'):
                        jar_path = os.path.join(root, file)
                        vuln_info = self.check_jar_vulnerability(jar_path)
                        if vuln_info:
                            vuln_info.update({
                                "container_type": "directory",
                                "container_path": directory,
                                "inner_jar_path": jar_path
                            })
                            vulnerabilities.append(vuln_info)
        except (OSError, PermissionError):
            pass

        return vulnerabilities

    def scan_containers(self):
        """扫描Docker容器"""
        try:
            # 检查docker命令是否可用
            subprocess.run(['docker', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

            # 获取运行中的容器
            docker_output = subprocess.check_output(['docker', 'ps', '--format', '{{.ID}}'], stderr=subprocess.DEVNULL).decode('utf-8')

            containers = docker_output.strip().split('\n')
            for container_id in containers:
                if not container_id:
                    continue

                try:
                    # 获取容器的Java进程
                    top_output = subprocess.check_output(['docker', 'top', container_id], stderr=subprocess.DEVNULL).decode('utf-8')

                    java_pids = []
                    for line in top_output.split('\n'):
                        if 'java' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                java_pids.append(parts[1])

                    if java_pids:
                        # 获取容器的文件系统路径
                        inspect_output = subprocess.check_output(['docker', 'inspect', container_id], stderr=subprocess.DEVNULL).decode('utf-8')

                        # 简单提取MergeDir（需要改进解析）
                        merged_dir_match = re.search(r'"MergedDir":\s*"([^"]+)"', inspect_output)
                        merged_dir = merged_dir_match.group(1) if merged_dir_match else None

                        if merged_dir and os.path.exists(merged_dir):
                            container_info = {
                                "container_id": container_id,
                                "merged_dir": merged_dir,
                                "java_pids": java_pids
                            }
                            self.results["scan_summary"]["scan_containers"].append(container_info)

                            # 扫描容器目录
                            vulnerabilities = self.check_directory(merged_dir)
                            for vuln in vulnerabilities:
                                vuln["container_type"] = "docker"
                                vuln["container_id"] = container_id
                                self.results["vulnerable_jars"].append(vuln)

                except subprocess.CalledProcessError:
                    continue

        except (subprocess.CalledProcessError, FileNotFoundError):
            # Docker不可用时跳过
            pass

    def scan_java_processes(self):
        """扫描Java进程"""
        processes = self.find_java_processes()

        for process in processes:
            # 检查主jar文件
            if process["jar_file"]:
                jar_path = process["jar_file"]

                # 如果是相对路径，尝试从进程的工作目录解析
                if not jar_path.startswith('/'):
                    try:
                        cwd = os.readlink(f'/proc/{process["pid"]}/cwd')
                        jar_path = os.path.join(cwd, jar_path)
                    except (OSError, FileNotFoundError):
                        continue

                if os.path.exists(jar_path):
                    # 检查fatjar
                    fatjar_vulns = self.check_fatjar(jar_path)
                    for vuln in fatjar_vulns:
                        vuln["process_pid"] = process["pid"]
                        vuln["process_cmdline"] = process["cmdline"]
                        self.results["vulnerable_jars"].append(vuln)

            # 检查classpath中的jar
            if process["classpath"]:
                classpath_entries = process["classpath"].split(':')
                for entry in classpath_entries:
                    if entry.endswith('.jar') and os.path.exists(entry):
                        vuln_info = self.check_jar_vulnerability(entry)
                        if vuln_info:
                            vuln_info.update({
                                "container_type": "classpath",
                                "process_pid": process["pid"],
                                "process_cmdline": process["cmdline"],
                                "inner_jar_path": entry
                            })
                            self.results["vulnerable_jars"].append(vuln_info)

    def scan_directories(self, scan_dirs: List[str] = None):
        """扫描指定目录"""
        if scan_dirs is None:
            scan_dirs = EXTRA_SCAN_DIRS

        self.results["scan_summary"]["scan_directories"] = scan_dirs

        for directory in scan_dirs:
            if os.path.exists(directory) and os.path.isdir(directory):
                vulnerabilities = self.check_directory(directory)
                for vuln in vulnerabilities:
                    self.results["vulnerable_jars"].append(vuln)

    def scan(self, scan_dirs: List[str] = None, include_containers: bool = True, include_processes: bool = True):
        """执行完整扫描"""
        if include_containers:
            self.scan_containers()

        if include_processes:
            self.scan_java_processes()

        self.scan_directories(scan_dirs)

        # 统计结果
        self._summarize_results()

    def _summarize_results(self):
        """汇总扫描结果"""
        self.results["scan_summary"]["total_vulnerabilities"] = len(self.results["vulnerable_jars"])

        # 统计不同类型的漏洞
        jar_files = set()
        fatjars = set()

        for vuln in self.results["vulnerable_jars"]:
            if vuln["container_type"] == "fatjar":
                fatjars.add(vuln["container_path"])
            else:
                jar_files.add(vuln["inner_jar_path"])

        self.results["scan_summary"]["vulnerable_jar_files"] = len(jar_files)
        self.results["scan_summary"]["vulnerable_fatjars"] = len(fatjars)

    def get_results(self) -> Dict:
        """获取扫描结果"""
        return self.results

def main():
    parser = argparse.ArgumentParser(description="检查漏洞jar包")
    parser.add_argument('-o', '--output', type=str, choices=['json'], default='json', help='输出格式')
    parser.add_argument('--scan-dirs', type=str, help='扫描目录，多个目录用逗号分隔')
    parser.add_argument('--no-containers', action='store_true', help='跳过容器扫描')
    parser.add_argument('--no-processes', action='store_true', help='跳过Java进程扫描')
    parser.add_argument('--verbose', action='store_true', help='详细输出')

    args = parser.parse_args()

    # 解析扫描目录
    scan_dirs = None
    if args.scan_dirs:
        scan_dirs = [dir.strip() for dir in args.scan_dirs.split(',') if dir.strip()]

    # 执行扫描
    scanner = VulnerableJarScanner()

    if args.verbose:
        print("开始扫描漏洞jar包...")
        if scan_dirs:
            print(f"扫描目录: {', '.join(scan_dirs)}")
        print(f"容器扫描: {'禁用' if args.no_containers else '启用'}")
        print(f"进程扫描: {'禁用' if args.no_processes else '启用'}")

    scanner.scan(
        scan_dirs=scan_dirs,
        include_containers=not args.no_containers,
        include_processes=not args.no_processes
    )

    results = scanner.get_results()

    if args.verbose:
        print(f"扫描完成，发现 {results['scan_summary']['total_vulnerabilities']} 个漏洞")

    # 输出结果
    output = {
        "vulnerable_jar_check": results,
        "scan_time": subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S']).decode('utf-8').strip()
    }

    if args.output == 'json':
        print(" " + json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()