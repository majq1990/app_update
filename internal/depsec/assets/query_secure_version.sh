#!/bin/bash
# 安全版本清单查询：给 jar 文件名或组件标识，判定是否低于当前确认的安全版本。
# 数据源：同目录 conf/secure-versions.flat（由 sync_inventory.py 从 AI 表格生成）。
# 用法：
#   bash query_secure_version.sh <jar文件名或组件标识>   # 单查，结果输出到 stdout
#   bash query_secure_version.sh local                   # 交互模式（工具箱菜单调用）
# 返回码：0=已给出结论（OK 或 发现低版本）；2=清单未收录该组件；1=参数错误
set -u
_cur_shell_path=$0
_cur_shell_name=${_cur_shell_path##*/}
_cur_shell_dir=${_cur_shell_path%/*}
if [ "${_cur_shell_name}" == "${_cur_shell_dir}" ];then
    _cur_shell_dir=$(pwd)
fi
# 清单位置：默认同目录 conf/secure-versions.flat；可用环境变量 SECURE_VERSIONS_FLAT 覆盖
#（如加固工具箱其他脚本把 flat 分发到别处时）。
FLAT="${SECURE_VERSIONS_FLAT:-${_cur_shell_dir}/conf/secure-versions.flat}"

# 版本比较：v1 < v2 返回 0（真），否则返回 1。按 .- 切段逐段比；
# 缺段：对方是纯数字段则视为更大（1.2 < 1.2.0），是 -jre/-RELEASE 这类后缀则忽略（32.0.1 == 32.0.1-jre）。
ver_lt() {
    local v1=$1 v2=$2
    [ "$v1" == "$v2" ] && return 1
    local IFS='.-'
    local -a a1=($v1) a2=($v2)
    local i s1 s2
    local n=${#a1[@]}; [ ${#a2[@]} -gt $n ] && n=${#a2[@]}
    for ((i=0; i<n; i++)); do
        s1=${a1[$i]:-}; s2=${a2[$i]:-}
        if [ -z "$s1" ] && [ -z "$s2" ]; then continue; fi
        if [ -z "$s1" ]; then
            [[ "$s2" =~ ^[0-9]+$ ]] && return 0
            continue
        fi
        if [ -z "$s2" ]; then
            [[ "$s1" =~ ^[0-9]+$ ]] && return 1
            continue
        fi
        if [[ "$s1" =~ ^[0-9]+$ && "$s2" =~ ^[0-9]+$ ]]; then
            [ "$s1" -lt "$s2" ] && return 0
            [ "$s1" -gt "$s2" ] && return 1
        else
            [[ "$s1" < "$s2" ]] && return 0
            [[ "$s1" > "$s2" ]] && return 1
        fi
    done
    return 1
}

# 从 jar 文件名推导组件 id（与 scan_vulnerable_jar.sh 的 get_jar_name 一致：去掉最后一个 - 段；
# 另兼容 guava-29.0-jre.jar 这类 -jre/-jdk 后缀，classifier 包在 query_one 的回退匹配里处理）
jar_to_id() {
    local full=$1
    full=${full##*/}
    full=${full%.jar}
    full=${full%-jre}
    full=${full%-jdk*}
    echo "${full%-*}"
}
# 从 jar 文件名提取版本段（最后一个 - 之后）
jar_to_ver() {
    local full=$1
    full=${full##*/}
    full=${full%.jar}
    echo "${full##*-}"
}

query_one() {
    local q=$1
    [ -f "$FLAT" ] || { echo "清单文件不存在: $FLAT"; return 1; }
    local id ver
    if [[ "$q" == *.jar ]]; then
        id=$(jar_to_id "$q"); ver=$(jar_to_ver "$q")
    else
        id=$q; ver=""
    fi
    # 精确匹配；命中则直接用
    # 版本规范化：-jre/-jdk 后缀与 classifier 不属于版本号，先剥离；
    # 若版本段不以数字开头（如 jre），改按“清单 id 之后”的剩余部分重取
    if [[ "$q" == *.jar && ! "$ver" =~ ^[0-9] ]]; then
        local _rest=${q##*/}
        _rest=${_rest%.jar}
        ver=${_rest#${id}-}
        ver=$(echo "$ver" | sed -E 's/-(linux|windows|macosx|android)-(x86_64|aarch64|arm64|x86)$//; s/-(jre|jdk[0-9]*|android)$//')
    fi
    local line=$(grep -m1 -E "^jar\|${id}\|" "$FLAT")
    [ -z "$line" ] && line=$(grep -m1 -E "^software\|${id}\|" "$FLAT")
    local matched_id=$id
    # 回退匹配：javacpp classifier 包（ffmpeg-3.2.1-1.3-linux-x86_64.jar）等文件名带多段版本，
    # 逐级剥离尾段直到命中清单 id；版本取“清单 id 之后、classifier 之前”的部分
    if [ -z "$line" ]; then
        local try=$id
        for _i in 1 2 3 4 5; do
            [[ "$try" != *-* ]] && break
            try=${try%-*}
            line=$(grep -m1 -E "^(jar|software)\|${try}\|" "$FLAT")
            if [ -n "$line" ]; then
                matched_id=$try
                local rest=${q##*/}
                rest=${rest%.jar}
                ver=${rest#${matched_id}-}
                ver=$(echo "$ver" | sed -E 's/-(linux|windows|macosx|android)-(x86_64|aarch64|arm64|x86)$//')
                break
            fi
        done
    fi
    if [ -z "$line" ]; then
        echo "UNKNOWN: 清单未收录 [${q}]，请先在 AI 表格「三方依赖安全版本清单」补录后再 sync"
        return 2
    fi
    local type lid secure vuln cves download update status
    IFS='|' read -r type lid secure vuln cves download update status <<< "$line"
    echo "组件: ${lid}（${type}） 状态: ${status}"
    echo "当前安全版本: ${secure:-（待定）}"
    [ -n "$vuln" ] && echo "漏洞版本范围: ${vuln}"
    [ -n "$cves" ] && echo "修复CVE: ${cves}"
    if [ -n "$ver" ]; then
        echo "待查版本: ${ver}"
        if [ -z "$secure" ]; then
            if [ "$status" == "已确认" ]; then
                echo "结论: 无可用安全版本（见更新方式：迁移/删除依赖）"
            else
                echo "结论: 待定（清单尚无安全版本结论，请走人工研判）"
            fi
        elif ver_lt "$ver" "$secure"; then
            echo "结论: VULNERABLE（低于安全版本，请升级到 ${secure}）"
        else
            echo "结论: OK（不低于安全版本 ${secure}）"
        fi
    fi
    [ -n "$download" ] && echo "下载: ${download}"
    [ -n "$update" ] && echo "更新方式: ${update}"
    return 0
}

function support_multi_mode(){ echo 0; }
_is_sourced() {
    [ "${#FUNCNAME[@]}" -ge 2 ] \
        && [ "${FUNCNAME[0]}" = '_is_sourced' ] \
        && [ "${FUNCNAME[1]}" = 'source' ]
}

if ! _is_sourced; then
    if [ $# -eq 0 ]; then
        echo "用法: bash ${_cur_shell_name} <jar文件名或组件标识> | local"
        exit 1
    fi
    if [ "$1" == "local" ]; then
        while true; do
            read -p "请输入 jar 文件名或组件标识（q 退出）: " q
            [ "$q" == "q" ] && break
            [ -z "$q" ] && continue
            query_one "$q"
            echo "---"
        done
    else
        query_one "$1"
        exit $?
    fi
fi
