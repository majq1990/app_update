#!/bin/bash

# 定义文件列表（所有需要判断的文件）
file_list=(
    "spy_jvm.sh"
)

# 定义目标目录
target_dir="/egova/tools/script/"

# JSON转义函数（避免特殊字符破坏格式）
json_escape() {
    local input="$1"
    input="${input//\\/\\\\}"
    input="${input//\"/\\\"}"
    echo -n "$input"
}

# 初始化计数器和结果变量
total_files=${#file_list[@]}
found_files=0
missing_files=0
file_details_json=""
first_file="true"

# 遍历文件列表
for index in "${!file_list[@]}"; do
    file="${file_list[$index]}"
    file_path="${target_dir}${file}"
    file_name_escaped=$(json_escape "$file")

    # 判断文件是否存在
    if [ -f "$file_path" ]; then
        status="YES"
        found_files=$((found_files + 1))
    else
        status="NO"
        missing_files=$((missing_files + 1))
    fi

    # 构建单个文件的JSON对象（完全匹配你要的格式：大括号内分行、紧凑缩进）
    single_file_json="      {\"01:工具脚本名称\": \"${file_name_escaped}\","
    single_file_json+="\n       \"02:存在状态::WRAPDATA_lt__quot_YES_quot_\": \"${status}\""
    single_file_json+="\n         }"

    # 处理逗号分隔（最后一个文件不加逗号，保证JSON格式合法）
    if [ "$first_file" = "true" ]; then
        file_details_json="${single_file_json}"
        first_file="false"
    else
        file_details_json="${file_details_json},\n${single_file_json}"
    fi
done

# 计算完整度百分比
check_percentage=0
if [ $total_files -gt 0 ]; then
    check_percentage=$((found_files * 100 / total_files))
fi

# 整体检查状态
overall_status=$([ $missing_files -eq 0 ] && echo "YES" || echo "NO")

# 生成JSON输出（完全匹配要求格式，已移除iotop相关节点）
cat <<EOF
{
  "basic": {},
  "topics": {
    "01:脚本文件存在性检查": [
      {
        "01:脚本文件检查状态::WRAPDATA_ne__quot_YES_quot_": "$(json_escape "$overall_status")",
        "02:检查目录": "$(json_escape "$target_dir")",
        "03:总文件数": "$total_files",
        "04:存在文件数": "$found_files",
        "05:缺失文件数": "$missing_files",
        "06:完整度": "${check_percentage}%"
      }
    ],
    "02:详细文件列表": [
$(echo -e "$file_details_json")
    ]
  }
}
EOF

exit 0
