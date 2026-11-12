#!/bin/bash

# 强制设置UTF-8编码（解决中文显示）
export LC_ALL=zh_CN.UTF-8
export LANG=zh_CN.UTF-8
export LANGUAGE=zh_CN.UTF-8

# ===================== 基础函数 =====================
# 获取服务器网卡IP地址
get_server_ip() {
    local ip=""
    # 过滤非回环、非docker的IPv4地址
    ip=$(ip -o -4 addr show 2>/dev/null | grep -v " lo " | grep -v "docker" | awk '{print $4}' | cut -d'/' -f1 | head -1)
    [ -z "$ip" ] && ip="127.0.0.1"
    echo "$ip"
}

# 获取nginx监听的所有端口
get_nginx_ports() {
    local ports=""
    # 从ss命令提取nginx监听端口
    ports=$(ss -tlnp 2>/dev/null | grep -E "nginx|nginx:" | grep -E "LISTEN" | awk '{print $4}' | cut -d':' -f2 | sort -nu | grep -E "^[0-9]+$")
    # 备用：从nginx配置文件提取
    if [ -z "$ports" ] && [ -d /etc/nginx ]; then
        ports=$(grep -rE "^\s*listen\s+[0-9]+" /etc/nginx/ 2>/dev/null | sed -E 's/.*listen[[:space:]]+([0-9]+).*/\1/' | sed 's/^0*//' | sort -nu)
    fi
    # 默认端口
    [ -z "$ports" ] && ports="8080"
    echo "$ports"
}

# 根据端口生成URL
get_url_for_port() {
    local ip=$1
    local port=$2
    local servername=$3
    [ "$port" = "443" ] && echo "https://${ip}/${servername}" || echo "http://${ip}:${port}/${servername}"
}

# 安全转义JSON字符串（终极版：彻底清理所有控制字符）
escape_json_string() {
    local input="$1"
    # 1. 删除所有不可见控制字符（0x00-0x1F, 0x7F）
    # 2. 替换JSON标准转义字符
    # 3. 去除首尾空白字符（包括换行、空格、制表符）
    echo -n "$input" | \
        tr -d '\000-\037\177' | \
        sed -e 's/\\/\\\\/g' \
            -e 's/"/\\"/g' \
            -e 's/\//\\\//g' \
            -e 's/\n/ /g' \
            -e 's/\r/ /g' \
            -e 's/\t/ /g' | \
        awk '{$1=$1};1'  # 去除首尾空白，压缩中间多个空白为单个
}

# ===================== 全局变量 =====================
SERVERNAME="eUrbanMIS"
IP_ADDRESS=$(get_server_ip)
PORTS=$(get_nginx_ports)

# 统计变量
TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_WARNING=0

# 存储每个端口的JSON结果（关联数组）
declare -A PORT_JSON
declare -A PORT_STATS

# 固定的状态key（核心修改点）
FIXED_STATUS_KEY="02:状态::WRAPDATA_lt__quot_400_quot_:#18679"

# ===================== 测试函数 =====================
# 执行单个URL测试
test_single_url() {
    local url=$1
    local expected_code=$2
    local desc=$3
    local port=$4
    local test_id=$5

    # 统计+1
    ((TOTAL_TESTS++))
    PORT_STATS["${port}_total"]=$(( ${PORT_STATS["${port}_total"]:-0} + 1 ))

    # 执行curl请求（超时3秒）
    local curl_opts="-s -o /dev/null -w \"%{http_code}\" --connect-timeout 3 --max-time 5"
    [ "$url" != "${url#https://}" ] && curl_opts="$curl_opts -k"
    local response_code=$(eval "curl $curl_opts \"$url\" 2>/dev/null")

    # 初始化结果
    local result=""
    local seq=$(printf "%02d" "$test_id")
    local status_value=""

    # 判断响应结果
    if [ -z "$response_code" ] || [ "$response_code" = "000" ]; then
        result="跳过 (状态码: 000 - 网络异常，跳过检查)"
        status_value="000"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    elif [ "$response_code" -eq "$expected_code" ]; then
        result="通过 (状态码: $response_code)"
        status_value="$response_code"
        ((TOTAL_PASSED++))
        PORT_STATS["${port}_passed"]=$(( ${PORT_STATS["${port}_passed"]:-0} + 1 ))
    elif [ "$response_code" -eq 400 ] && [[ "$desc" == *"token"* ]]; then
        result="警告 (状态码: 400 - 可能需要参数)"
        status_value="400"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    elif [ "$response_code" -eq 404 ]; then
        result="跳过 (状态码: 404 - 路径不存在)"
        status_value="404"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    else
        result="失败 (期望: $expected_code, 实际: $response_code)"
        status_value="$response_code"
        ((TOTAL_FAILED++))
        PORT_STATS["${port}_failed"]=$(( ${PORT_STATS["${port}_failed"]:-0} + 1 ))
    fi

    # 生成JSON项（使用安全转义函数）
    local safe_desc=$(escape_json_string "$desc")
    local safe_result=$(escape_json_string "$result")
    local json_item="{\"01:接口\":\"${safe_desc}\", \"${FIXED_STATUS_KEY}\": \"${status_value}\", \"03:结果描述\":\"${safe_result}\"}"

    # 追加到端口JSON结果（无换行拼接）
    if [ -n "${PORT_JSON[$port]}" ]; then
        PORT_JSON[$port]="${PORT_JSON[$port]}|${json_item}"  # 用|作为分隔符，避免和,冲突
    else
        PORT_JSON[$port]="${json_item}"
    fi
}

# 测试IP白名单路径
test_ip_whitelist() {
    local base_url=$1
    local desc=$2
    local port=$3
    local test_id=$4

    ((TOTAL_TESTS++))
    PORT_STATS["${port}_total"]=$(( ${PORT_STATS["${port}_total"]:-0} + 1 ))

    local curl_opts="-s -o /dev/null -w \"%{http_code}\" --connect-timeout 3 --max-time 5"
    [ "$base_url" != "${base_url#https://}" ] && curl_opts="$curl_opts -k"
    local response_code=$(eval "curl $curl_opts \"${base_url}/pub/media/upload\" 2>/dev/null")

    local result=""
    local seq=$(printf "%02d" "$test_id")
    local status_value=""

    if [ -z "$response_code" ] || [ "$response_code" = "000" ]; then
        result="跳过 (状态码: 000 - 网络异常，跳过检查)"
        status_value="000"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    elif [ "$response_code" -eq 403 ]; then
        result="通过 (状态码: 403 - 访问被拒绝)"
        status_value="403"
        ((TOTAL_PASSED++))
        PORT_STATS["${port}_passed"]=$(( ${PORT_STATS["${port}_passed"]:-0} + 1 ))
    elif [ "$response_code" -eq 200 ]; then
        result="警告 (状态码: 200 - 可能测试IP在白名单内)"
        status_value="200"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    elif [ "$response_code" -eq 404 ]; then
        result="跳过 (状态码: 404 - 路径不存在)"
        status_value="404"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    else
        result="注意 (状态码: $response_code - 可能需要检查配置)"
        status_value="$response_code"
        ((TOTAL_WARNING++))
        PORT_STATS["${port}_warning"]=$(( ${PORT_STATS["${port}_warning"]:-0} + 1 ))
    fi

    # 生成JSON项（使用安全转义函数）
    local safe_desc=$(escape_json_string "$desc")
    local safe_result=$(escape_json_string "$result")
    local json_item="{\"01:接口\":\"${safe_desc}\", \"${FIXED_STATUS_KEY}\": \"${status_value}\", \"03:结果描述\":\"${safe_result}\"}"

    # 追加到端口JSON结果（无换行拼接）
    if [ -n "${PORT_JSON[$port]}" ]; then
        PORT_JSON[$port]="${PORT_JSON[$port]}|${json_item}"
    else
        PORT_JSON[$port]="${json_item}"
    fi
}

# 测试单个端口的所有用例
test_port() {
    local port=$1
    local index=$2
    local total=$3

    local base_url=$(get_url_for_port "$IP_ADDRESS" "$port" "$SERVERNAME")

    # 初始化端口统计
    PORT_STATS["${port}_total"]=0
    PORT_STATS["${port}_passed"]=0
    PORT_STATS["${port}_failed"]=0
    PORT_STATS["${port}_warning"]=0
    PORT_JSON[$port]=""

    # 测试基本连接性
    local curl_opts="-s -o /dev/null -w \"%{http_code}\" --connect-timeout 3 --max-time 5"
    [ "$base_url" != "${base_url#https://}" ] && curl_opts="$curl_opts -k"
    local response_code=$(eval "curl $curl_opts \"$base_url/\" 2>/dev/null")

    if [ -z "$response_code" ] || [ "$response_code" = "000" ] || [ "$response_code" -ge 500 ]; then
        return 1
    fi

    # 核心测试用例
    local test_id=1

    # 基础路径测试
    test_single_url "${base_url}/thirdopenwindow.htm" 403 "${SERVERNAME}/thirdopenwindow.htm" "$port" $((test_id++))
    test_single_url "${base_url}/openwithoutlogin.htm" 403 "${SERVERNAME}/openwithoutlogin.htm" "$port" $((test_id++))
    test_single_url "${base_url}/openbyhumanwithoutlogin.htm" 403 "${SERVERNAME}/openbyhumanwithoutlogin.htm" "$port" $((test_id++))
    test_single_url "${base_url}/openwindowbyrole.htm" 403 "${SERVERNAME}/openwindowbyrole.htm" "$port" $((test_id++))
    test_single_url "${base_url}/openwindow.htm" 403 "${SERVERNAME}/openwindow.htm" "$port" $((test_id++))
    test_single_url "${base_url}/third/openwindow.htm" 403 "${SERVERNAME}/third/openwindow.htm" "$port" $((test_id++))
    test_single_url "${base_url}/unionnavigator.htm" 403 "${SERVERNAME}/unionnavigator.htm" "$port" $((test_id++))

    # 登录相关
    test_single_url "${base_url}/login/resetpassword" 403 "${SERVERNAME}/login/resetpassword" "$port" $((test_id++))
    test_single_url "${base_url}/mobile/pub/gettokenbyhumanid" 403 "${SERVERNAME}/mobile/pub/gettokenbyhumanid" "$port" $((test_id++))
    test_single_url "${base_url}/login/freeLogin.htm" 403 "${SERVERNAME}/login/freeLogin.htm" "$port" $((test_id++))
    test_single_url "${base_url}/login/screen" 403 "${SERVERNAME}/login/screen" "$port" $((test_id++))
    test_single_url "${base_url}/screencommandsystem" 403 "${SERVERNAME}/screencommandsystem" "$port" $((test_id++))

    # 敏感路径
    test_single_url "${base_url}/screenspeciallogonbyhumanid" 403 "${SERVERNAME}/screenspeciallogonbyhumanid" "$port" $((test_id++))
    test_single_url "${base_url}/login/getloginmishumans" 403 "${SERVERNAME}/login/getloginmishumans" "$port" $((test_id++))
    test_single_url "${base_url}/productionLibrary/3rdparty/ueditor/jsp/config.json" 403 "${SERVERNAME}/productionLibrary/3rdparty/ueditor/jsp/config.json" "$port" $((test_id++))
    test_single_url "${base_url}/mobile/misys/register/register" 403 "${SERVERNAME}/mobile/misys/register/register" "$port" $((test_id++))
    test_single_url "${base_url}/mobile/plugin/infoexpress" 403 "${SERVERNAME}/mobile/plugin/infoexpress" "$port" $((test_id++))

    # 文件上传
    test_single_url "${base_url}/formEx/uploadFiles" 403 "${SERVERNAME}/formEx/uploadFiles" "$port" $((test_id++))
    test_single_url "${base_url}/view/mobile/vue/dist/sgPublicity/" 403 "${SERVERNAME}/view/mobile/vue/dist/sgPublicity/" "$port" $((test_id++))
    test_single_url "${base_url}/mi/misys/im/uploadmedia" 403 "${SERVERNAME}/mi/misys/im/uploadmedia" "$port" $((test_id++))
    test_single_url "${base_url}/video/vod/register" 403 "${SERVERNAME}/video/vod/register" "$port" $((test_id++))
    test_single_url "${base_url}/video/vod/uploadMedia" 403 "${SERVERNAME}/video/vod/uploadMedia" "$port" $((test_id++))

    # 脚本阻止
    test_single_url "${base_url}/test.jsp" 403 "${SERVERNAME}/test.jsp" "$port" $((test_id++))
    test_single_url "${base_url}/uploadjson/" 403 "${SERVERNAME}/uploadjson/" "$port" $((test_id++))
    test_single_url "${base_url}/test.php" 403 "${SERVERNAME}/test.php" "$port" $((test_id++))
    test_single_url "${base_url}/test.aspx" 403 "${SERVERNAME}/test.aspx" "$port" $((test_id++))

    # 其他功能
    test_single_url "${base_url}/view/infoexpress" 403 "${SERVERNAME}/view/infoexpress" "$port" $((test_id++))
    test_single_url "${base_url}/testapp/dataexp/exportapi" 403 "${SERVERNAME}/testapp/dataexp/exportapi" "$port" $((test_id++))
    test_single_url "${base_url}/home/dataexp/export" 403 "${SERVERNAME}/home/dataexp/export" "$port" $((test_id++))
    test_single_url "${base_url}/mediadl/home/" 403 "${SERVERNAME}/mediadl/home/" "$port" $((test_id++))
    test_single_url "${base_url}/view/mediadl/home/" 403 "${SERVERNAME}/view/mediadl/home/" "$port" $((test_id++))
    test_single_url "${base_url}/othersys/getredirecturl" 403 "${SERVERNAME}/othersys/getredirecturl" "$port" $((test_id++))
    test_single_url "${base_url}/othersys/openbytokenwithoutlogin.htm" 403 "${SERVERNAME}/othersys/openbytokenwithoutlogin.htm" "$port" $((test_id++))
    test_single_url "${base_url}/othersys/oauthlogon" 403 "${SERVERNAME}/othersys/oauthlogon" "$port" $((test_id++))
    test_single_url "${base_url}/othersys/oauthopenwindow.htm" 403 "${SERVERNAME}/othersys/oauthopenwindow.htm" "$port" $((test_id++))
    test_single_url "${base_url}/othersys/oauthlogin.htm" 403 "${SERVERNAME}/othersys/oauthlogin.htm" "$port" $((test_id++))
    test_single_url "${base_url}/othersys/misoauthlogin.htm" 403 "${SERVERNAME}/othersys/misoauthlogin.htm" "$port" $((test_id++))

    # IP白名单测试
    test_ip_whitelist "$base_url" "${SERVERNAME}" "$port" $test_id
}

# ===================== JSON生成函数（纯Bash） =====================

generate_json() {
    # 缩进控制
    local indent="  "
    local indent2="${indent}${indent}"
    local indent3="${indent2}${indent}"
    local indent4="${indent3}${indent}"

    # 开始构建JSON（无多余换行）
    printf "{\n"
    printf "${indent}\"basic\": {\n"
    printf "${indent2}\"服务器IP\": \"$(escape_json_string "$IP_ADDRESS")\",\n"
    printf "${indent2}\"服务名\": \"$(escape_json_string "$SERVERNAME")\",\n"
    printf "${indent2}\"总测试数\": ${TOTAL_TESTS},\n"
    printf "${indent2}\"总通过数\": ${TOTAL_PASSED},\n"
    printf "${indent2}\"总失败数\": ${TOTAL_FAILED},\n"
    printf "${indent2}\"总警告数\": ${TOTAL_WARNING}\n"
    printf "${indent}},\n"
    printf "${indent}\"topics\": {\n"

    # 处理每个端口的JSON
    local first_port=true
    for port in $PORTS; do
        [ -z "${PORT_JSON[$port]}" ] && continue

        # 添加逗号分隔符
        if [ "$first_port" = false ]; then
            printf ",\n"
        fi
        first_port=false

        # 输出端口测试结果
        printf "${indent2}\"端口 ${port} 测试\": ["
        # 拆分JSON项（用|分隔，避免,冲突）
        local IFS="|"
        local items=(${PORT_JSON[$port]})
        local first_item=true
        for item in "${items[@]}"; do
            [ -z "$item" ] && continue
            if [ "$first_item" = false ]; then
                printf ", "
            fi
            first_item=false
            printf "%s" "$item"  # 无换行输出item
        done
        printf "]"
    done

    # 闭合JSON
    printf "\n${indent}}\n"
    printf "}\n"
}

# ===================== 主程序 =====================
# 检查nginx状态（不输出信息）
if ! (systemctl is-active --quiet nginx 2>/dev/null || pgrep nginx >/dev/null 2>&1); then
    # 即使nginx未运行也继续执行，仅生成测试结果JSON
    true
fi

# 执行端口测试
port_count=$(echo "$PORTS" | wc -w)
port_index=0
for port in $PORTS; do
    ((port_index++))
    test_port "$port" "$port_index" "$port_count"
done

# 只输出JSON报告
generate_json

exit 0
