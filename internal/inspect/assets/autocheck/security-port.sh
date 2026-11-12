#!/bin/bash

# 检查端口加固状态
# 输出JSON格式的检查结果，基于enhance_port.sh的加固措施进行检查

# enhance_port.sh中使用的ipset名称
ipset_name_of_egova_vpc_nets="egova-vpc-nets"
ipset_name_of_egova_local_ports="egova-local-ports"
ipset_name_of_egova_expose_ports="egova-expose-ports"

# ===================== 核心JSON清理函数（保留并优化） =====================
function clean_json_value() {
    local input="$1"
    # 1. 删除所有ASCII控制字符（0x00-0x1F, 0x7F）
    # 2. 转义双引号，避免破坏JSON结构
    # 3. 将换行/回车/制表符替换为单个空格
    # 4. 压缩多个空格为单个
    # 5. 去除首尾空格
    echo -n "$input" | \
        tr -d '\000-\037\177' 2>/dev/null | \
        sed -e 's/"/\\"/g' \
            -e 's/\n/ /g' \
            -e 's/\r/ /g' \
            -e 's/\t/ /g' \
            -e 's/[[:space:]]\+/ /g' 2>/dev/null | \
        awk '{$1=$1};1' 2>/dev/null
}

# 初始化结果变量
port_security_checks=""

# ===================== 检查ipset存在性（保留，逻辑正常） =====================
function check_ipset_exists() {
  local ipset_name=$1
  local status="NO"

  if command -v ipset &>/dev/null && ipset list -n 2>/dev/null | grep -q "^${ipset_name}$"; then
    status="YES"
  fi

  echo "$(clean_json_value "$status")"
}

# ===================== 检查iptables规则（保留，适配后续参数修复） =====================
function check_iptables_rule() {
  local rule_name=$1
  local rule_check=$2
  local status="NO"

  if command -v iptables &>/dev/null && iptables -L INPUT -n 2>/dev/null | grep -q "${rule_check}"; then
    status="YES"
  fi

  echo "$(clean_json_value "$status")"
}

# ===================== 优化：check_local_ports 函数（修复3大漏洞） =====================
function check_local_ports() {
  local status="NO"
  local local_ports=""
  local missing_ports=""

  # 优化1：严谨提取本地非SSH监听端口（过滤默认22端口，避免sshd误报）
  local_ports=$(netstat -tuln 2>/dev/null | grep LISTEN | awk '{print $4}' | \
    grep -v -E "127.0.0.1:|::1:" | awk -F: '{print $NF}' | sort | uniq | \
    tr '\n' ' ' | tr ' ' '\n' | grep -v "^22$" | tr '\n' ' ')

  # 检查这些端口是否在ipset中
  if command -v ipset &>/dev/null; then
    # 优化2：先判断两个ipset是否存在，避免不存在时报错引发误判
    local local_ports_exists=$(check_ipset_exists "${ipset_name_of_egova_local_ports}")
    local expose_ports_exists=$(check_ipset_exists "${ipset_name_of_egova_expose_ports}")

    for port in $local_ports; do
      local in_local_ports="NO"
      local in_expose_ports="NO"

      # 仅当ipset存在时，才进行匹配
      if [ "$local_ports_exists" = "YES" ]; then
        if ipset list ${ipset_name_of_egova_local_ports} 2>/dev/null | grep -q "^${port}$"; then
          in_local_ports="YES"
        fi
      fi

       # 修复：适配egova-expose-ports的bitmap:port格式（匹配纯端口）
     if [ "$expose_ports_exists" = "YES" ]; then
       if ipset list ${ipset_name_of_egova_expose_ports} 2>/dev/null | grep -q "^${port}$"; then
        in_expose_ports="YES"
        fi
        fi
    done
  else
    missing_ports="$local_ports"
  fi

  # 去除首尾空格
  missing_ports=$(echo "$missing_ports" | sed 's/^ *//;s/ *$//')

  if [ -z "$missing_ports" ]; then
    status="YES"
  fi

  echo "$(clean_json_value "$status")"
}

# ===================== check_vpc_nets 函数（保留，逻辑正常） =====================
function check_vpc_nets() {
  local status="NO"
  local vpc_nets_count=0

  if command -v ipset &>/dev/null; then
    vpc_nets_count=$(ipset list ${ipset_name_of_egova_vpc_nets} 2>/dev/null | grep -c -E "^[0-9]" 2>/dev/null || echo 0)
  fi

  echo "$(clean_json_value "$vpc_nets_count")"
}

# ===================== check_default_drop_rule 函数（保留，逻辑正常） =====================
function check_default_drop_rule() {
  local status="NO"

  if command -v iptables &>/dev/null; then
    local iptables_rules=$(iptables -L INPUT -n 2>/dev/null)

    if echo "$iptables_rules" | grep -q "DROP.*match-set ${ipset_name_of_egova_local_ports} dst"; then
      status="YES"
    fi
  fi

  echo "$(clean_json_value "$status")"
}

# ===================== check_services_enabled 函数（保留，逻辑正常） =====================
function check_services_enabled() {
  local status="NO"

  if command -v systemctl &>/dev/null; then
    if systemctl is-enabled iptables &>/dev/null && systemctl is-active iptables &>/dev/null &&
      systemctl is-enabled ipset &>/dev/null && systemctl is-active ipset &>/dev/null; then
      status="YES"
    fi
  else
    if command -v service &>/dev/null && service iptables status &>/dev/null && service ipset status &>/dev/null; then
      status="YES"
    fi
  fi

  echo "$(clean_json_value "$status")"
}

# ===================== check_firewalld_disabled 函数（保留，逻辑正常） =====================
function check_firewalld_disabled() {
  local status="NO"

  if command -v systemctl &>/dev/null; then
    if ! systemctl is-enabled firewalld &>/dev/null && ! systemctl is-active firewalld &>/dev/null; then
      status="YES"
    fi
  else
    if command -v service &>/dev/null && ! service firewalld status &>/dev/null; then
      status="YES"
    fi
  fi

  echo "$(clean_json_value "$status")"
}

# ===================== 优化：get_security_details 函数（修复egova-expose-ports正则问题） =====================
function get_security_details() {
  local details=()

  # 获取已配置的VPC网络（逻辑正常，保留）
  local vpc_nets=""
  if command -v ipset &>/dev/null; then
    vpc_nets=$(ipset list ${ipset_name_of_egova_vpc_nets} 2>/dev/null | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}($|/[0-9]{1,2}$)" | tr '\n' ',' | sed 's/,$//')
  fi

  # 获取本地端口列表（保留，增加容错提示可选项，不影响核心逻辑）
  local local_ports=""
  if command -v ipset &>/dev/null; then
    local_ports=$(ipset list ${ipset_name_of_egova_local_ports} 2>/dev/null | grep -E "^[0-9]+$" | tr '\n' ',' | sed 's/,$//')
  fi

  # 修复：精准提取egova-expose-ports成员（匹配bitmap:port格式）
   local expose_ports=""
    if command -v ipset &>/dev/null; then
     expose_ports=$(ipset list ${ipset_name_of_egova_expose_ports} 2>/dev/null | grep -E "^[0-9]+$" | tr '\n' ',' | sed 's/,$//')
    fi

  # 清理所有字段值
  local clean_vpc_nets=$(clean_json_value "$vpc_nets")
  local clean_local_ports=$(clean_json_value "$local_ports")
  local clean_expose_ports=$(clean_json_value "$expose_ports")

  cat <<EOF
{
      "01:vpc_networks": "${clean_vpc_nets}",
      "02:local_ports": "${clean_local_ports}",
      "03:exposed_ports": "${clean_expose_ports}"
    }
EOF
}

# ===================== 主函数（优化：修复egova-expose-ports的iptables检查参数） =====================
function main() {
  # 脚本主要流程
  local vpc_nets_status=$(check_ipset_exists "${ipset_name_of_egova_vpc_nets}")
  local local_ports_status=$(check_ipset_exists "${ipset_name_of_egova_local_ports}")
  local expose_ports_status=$(check_ipset_exists "${ipset_name_of_egova_expose_ports}")
  # 优化：修复iptables规则检查参数（src,dst），适配hash:ip,port类型
  local vpc_access_status=$(check_iptables_rule "vpc_access_rule" "match-set ${ipset_name_of_egova_local_ports} dst")
  local exposed_ports_status=$(check_iptables_rule "exposed_ports_rule" "match-set ${ipset_name_of_egova_expose_ports} src,dst")
  local local_ports_config=$(check_local_ports)
  local vpc_nets_count=$(check_vpc_nets)
  local default_drop_status=$(check_default_drop_rule)
  local services_status=$(check_services_enabled)
  local firewalld_status=$(check_firewalld_disabled)

  # 获取详细信息
  local security_details=$(get_security_details)

  # 使用JSON格式输出结果
  check_result=$(cat <<EOF
{
  "basic": {},
  "topics": {
    "01:port_security_checks": [
      {
        "01:ipset_egova_vpc_nets_status::WRAPDATA_eq__quot_NO_quot_:#17730": "${vpc_nets_status}",
        "02:ipset_egova_local_ports_status::WRAPDATA_eq__quot_NO_quot_:#17730": "${local_ports_status}",
        "03:ipset_egova_expose_ports_status::WRAPDATA_eq__quot_NO_quot_:#17730": "${expose_ports_status}",
        "04:vpc_access_rule::WRAPDATA_eq__quot_NO_quot_:#17730": "${vpc_access_status}",
        "05:local_ports_config::WRAPDATA_eq__quot_NO_quot_:#17730": "${local_ports_config}",
        "06:vpc_nets_count::DATA_eq_0:#17730": "${vpc_nets_count}",
        "07:default_drop_rule::WRAPDATA_eq__quot_NO_quot_:#17730": "${default_drop_status}",
        "08:ipset_services_enabled::WRAPDATA_eq__quot_NO_quot_:#17730": "${services_status}",
        "09:firewalld_disabled::WRAPDATA_eq__quot_NO_quot_:#17730": "${firewalld_status}"
      }
    ],
    "02:port_security_details": [
      ${security_details}
    ]
  }
}
EOF
)
  echo "$check_result"
}

# 执行主函数
main
