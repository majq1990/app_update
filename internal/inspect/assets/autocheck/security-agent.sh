#!/bin/bash

# 检查Tomcat进程和安全Agent状态
function get_tomcat_processes() {
  # 获取所有tomcat进程
  ps -ef | grep "[c]atalina.home" | awk '{print $2}'
}

# 检查微服务进程和安全Agent状态
function get_microservice_processes() {
  # 获取所有运行中的微服务进程（通过 -jar 参数识别）
  ps -ef | grep "[j]ava" | grep -E "\-jar\s+[^ ]+\.jar" | awk '{print $2}'
}

# 获取进程信息并判断是否包含安全Agent
function get_process_info() {
  local pid=$1
  local catalina_home=""
  local jar_file=""
  local has_security_agent="NO"

  # 获取进程的完整命令行
  
  local cmdline=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ')
  # 提取CATALINA_HOME（针对Tomcat）
  if [[ $cmdline =~ -Dcatalina.home=([^ ]+) ]]; then
    catalina_home="${BASH_REMATCH[1]}"
  fi

  # 提取微服务的 JAR 文件路径
  if [[ $cmdline =~ -jar[[:space:]]+([^ ]+\.jar) ]]; then
    jar_file="${BASH_REMATCH[1]}"
  fi

  # 检查是否包含security agent
  if [[ $cmdline =~ egova-security-agent.jar ]]; then
    has_security_agent="YES"
  fi

  # 输出JSON格式的进程信息
  cat <<EOF
{
        "01:process_id": "${pid}",
        "02:catalina_home": "${catalina_home}",
        "03:jar_file": "${jar_file}",
        "04:has_security_agent::WRAPDATA_eq__quot_NO_quot_:#17730": "${has_security_agent}"
}
EOF
}

function main() {
  local tomcat_processes=($(get_tomcat_processes))
  local microservice_processes=($(get_microservice_processes))
  local all_processes=("${tomcat_processes[@]}" "${microservice_processes[@]}")
  local process_count=${#all_processes[@]}
  local result_items=""

  # 去重（避免Tomcat和微服务进程重复）
  readarray -t all_processes < <(printf '%s\n' "${all_processes[@]}" | sort -u)

  # 处理每个进程
  for pid in "${all_processes[@]}"; do
    if [ -n "$result_items" ]; then
      result_items="${result_items},"
    fi
    result_items="${result_items}$(get_process_info $pid)"
  done

  # 输出最终的JSON结果
  cat <<EOF
{
  "basic": {},
  "topics": {
    "01:java_process_count": [
      {
        "01:count::DATA_eq_0:#17730": "${process_count}"
      }
    ],
    "02:processes": [
      ${result_items}
    ]
  }
}
EOF
}

# 执行主函数
main
