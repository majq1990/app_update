#!/bin/bash
# 安全版本构件获取（**默认只打印地址，不下载**）。
#
# 处置口径（2026-11-16 用户定稿）：
#   - 中间件 / 独立依赖软件（mysql、xtrabackup、redis、nginx、tomcat、zk、kafka…）：
#       工具支持联网更新；无外网环境只给中国大陆下载地址，由人执行。
#   - 代码内引用的 jar 包：工具**只记录问题清单**，不做替换/下载，一律要求提单由研发更新。
#
# 用法：
#   bash fetch_secure_artifact.sh <组件标识>                # 只打印下载地址+更新方式（默认）
#   bash fetch_secure_artifact.sh <组件标识> --download     # 显式下载到 /tmp/secure-artifacts（仅中间件/软件）
#   bash fetch_secure_artifact.sh <组件标识> --download <目录>
#   bash fetch_secure_artifact.sh local                     # 交互模式
# 返回码：0=正常；2=清单未收录；3=无安全版本；4=下载失败；5=jar 类禁止下载
set -u
_cur_shell_path=$0
_cur_shell_name=${_cur_shell_path##*/}
_cur_shell_dir=${_cur_shell_path%/*}
if [ "${_cur_shell_name}" == "${_cur_shell_dir}" ];then
    _cur_shell_dir=$(pwd)
fi
FLAT="${SECURE_VERSIONS_FLAT:-${_cur_shell_dir}/conf/secure-versions.flat}"

resolve() {
    local id=$1
    [ -f "$FLAT" ] || { echo "清单文件不存在: $FLAT"; return 1; }
    local line=$(grep -m1 -E "^(jar|software)\|${id}\|" "$FLAT")
    [ -z "$line" ] && return 2
    printf '%s\n' "$line"
}

fetch_one() {
    local id=$1 do_dl=${2:-0} outdir=${3:-/tmp/secure-artifacts}
    local line rc
    line=$(resolve "$id"); rc=$?
    [ $rc -eq 2 ] && { echo "UNKNOWN: 清单未收录 [$id]"; return 2; }
    [ $rc -ne 0 ] && return 1

    local type lid secure vuln cves download update status
    IFS='|' read -r type lid secure vuln cves download update status <<< "$line"

    echo "组件: ${lid}（${type}） 状态: ${status}"
    echo "当前安全版本: ${secure:-（待定）}"
    [ -n "$cves" ] && echo "修复CVE: ${cves}"

    if [ -z "$secure" ]; then
        echo "结论: 无可用安全版本（JDK/生态限制或组件已 EOL），按“更新方式”迁移或接受风险"
        [ -n "$update" ] && echo "更新方式: ${update}"
        return 3
    fi

    if [ "$type" == "jar" ]; then
        echo "处置口径: 代码内依赖 —— 工具不下载、不替换，请提单交研发更新"
        [ -n "$download" ] && echo "参考地址（仅供研发取件）: ${download}"
        [ -n "$update" ] && echo "更新方式: ${update}"
        return 5
    fi

    # 独立软件 / 中间件
    if [ -z "$download" ]; then
        echo "下载地址: 清单未登记，请先在 AI 表格补录"
        return 3
    fi
    if [ "$do_dl" != "1" ]; then
        echo "下载地址（中国大陆可访问，按序优先）:"
        local i=1 u
        for u in $download; do echo "  ${i}) ${u}"; i=$((i+1)); done
        echo "更新方式: ${update}"
        echo "提示: 默认只给地址不下载；需自动取件时加 --download"
        return 0
    fi

    mkdir -p "$outdir" || return 4
    local ok=0
    for u in $download; do
        echo "下载: $u"
        if curl -fSL --connect-timeout 10 --max-time 600 -o "${outdir}/$(basename "${u%%\?*}")" "$u"; then
            echo "已保存: ${outdir}/$(basename "${u%%\?*}")"
            ok=1; break
        fi
        echo "  该地址失败，尝试下一个…"
    done
    [ $ok -eq 0 ] && { echo "全部下载地址失败"; return 4; }
    [ -n "$update" ] && echo "更新方式: ${update}"
    return 0
}

function support_multi_mode(){ echo 0; }
_is_sourced() {
    [ "${#FUNCNAME[@]}" -ge 2 ] && [ "${FUNCNAME[0]}" = '_is_sourced' ] && [ "${FUNCNAME[1]}" = 'source' ]
}

if ! _is_sourced; then
    if [ $# -eq 0 ]; then
        echo "用法: bash ${_cur_shell_name} <组件标识> [--download [目录]] | local"
        exit 1
    fi
    if [ "$1" == "local" ]; then
        read -p "请输入组件标识（如 redis / mysql / tomcat）: " q
        fetch_one "$q" 0
        exit $?
    fi
    if [ "${2:-}" == "--download" ]; then
        fetch_one "$1" 1 "${3:-/tmp/secure-artifacts}"
    else
        fetch_one "$1" 0
    fi
    exit $?
fi
