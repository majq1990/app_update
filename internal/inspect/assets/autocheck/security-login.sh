#!/bin/bash

# 获取近一个月内登录失败次数最多的IP及其对应的用户名
get_top_failed_login_ips_and_users() {
    local log_dir="/var/log"
    local date_threshold=$(date -d "30 days ago" +"%b %d")
    local log_files=()
    local supported_logs=("secure" "auth.log" "messages" "syslog")

    # 遍历支持的日志文件名，找到存在的日志文件
    for log in "${supported_logs[@]}"; do
        # 匹配普通日志文件和带后缀的日志文件
        for file in "$log_dir/$log" "$log_dir/$log."* "$log_dir/$log-"*; do
            if [[ -f "$file" ]]; then
                log_files+=("$file")
            fi
        done
    done

    # 如果没有找到任何日志文件，返回空
    if [[ ${#log_files[@]} -eq 0 ]]; then
        return
    fi

    # 遍历所有找到的日志文件
    for log_file in "${log_files[@]}"; do
        if [[ $log_file == *.gz ]]; then
            # 如果是压缩文件，使用 zgrep
            zgrep -a -E "Failed password|authentication failure" "$log_file" | awk -v date_threshold="$date_threshold" '
                BEGIN { FS=" "; OFS="\t" }
                $1 " " $2 >= date_threshold {
                    # 提取用户名和IP地址
                    if ($0 ~ /Failed password/) {
                        user = $9
                        ip = $11
                    } else if ($0 ~ /authentication failure/) {
                        match($0, /user=(\S+)/, arr_user)
                        user = arr_user[1]
                        match($0, /rhost=(\S+)/, arr_ip)
                        ip = arr_ip[1]
                    }
                    # 替换可能的 "invalid" 或 "for" 关键字
                    if (user ~ /invalid|for/) user = "unknown"
                    # 过滤掉为空的IP地址或无效的用户
                    if (ip != "" && user != "" && user != "failure" && user != "-E") {
                        # 验证IP地址是否有效
                        if (ip ~ /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/) {
                            print user, ip
                        }
                    }
                }
            '
        else
            # 如果是普通文件，直接使用 grep
            grep -a -E "Failed password|authentication failure" "$log_file" | awk -v date_threshold="$date_threshold" '
                BEGIN { FS=" "; OFS="\t" }
                $1 " " $2 >= date_threshold {
                    # 提取用户名和IP地址
                    if ($0 ~ /Failed password/) {
                        user = $9
                        ip = $11
                    } else if ($0 ~ /authentication failure/) {
                        match($0, /user=(\S+)/, arr_user)
                        user = arr_user[1]
                        match($0, /rhost=(\S+)/, arr_ip)
                        ip = arr_ip[1]
                    }
                    # 替换可能的 "invalid" 或 "for" 关键字
                    if (user ~ /invalid|for/) user = "unknown"
                    # 过滤掉为空的IP地址或无效的用户
                    if (ip != "" && user != "" && user != "failure" && user != "-E") {
                        # 验证IP地址是否有效
                        if (ip ~ /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/) {
                            print user, ip
                        }
                    }
                }
            '
        fi
    done | sort | uniq -c | sort -nr | head -n 50
}

function main() {
    # 获取失败登录的IP和用户信息
    local top_failed_login_info=$(get_top_failed_login_ips_and_users)

    # 初始化JSON数组
    local json_array="["
    
    # 检查是否获取到失败登录信息
    if [[ -z "$top_failed_login_info" ]]; then
        # 当没有失败记录时，添加一个默认条目
        json_array+="{
            \"user\": \"none\",
            \"ip\": \"none\",
            \"failed_attempts\": 0
        }"
    else
        # 遍历每一行统计信息
        while IFS= read -r line; do
            count=$(echo "$line" | awk '{print $1}')
            user=$(echo "$line" | awk '{print $2}')
            ip=$(echo "$line" | awk '{print $3}')

            # 构建JSON对象
            local obj="{
                \"user\": \"$user\",
                \"ip\": \"$ip\",
                \"failed_attempts\": $count
            }"

            # 添加逗号分隔符（非首行时）
            if [[ -n "$json_array" && "$json_array" != "[" ]]; then
                obj=",$obj"
            fi

            json_array+="$obj"
        done <<< "$top_failed_login_info"
    fi

    # 闭合JSON数组并构造完整JSON
    local json_output=$(cat <<EOF
{
    "basic": {},
    "topics": {
        "01:failed_login_ips_and_users": ${json_array}]
    }
}
EOF
)

    echo "$json_output"
}

# 执行主函数
main
