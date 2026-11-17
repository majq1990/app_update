#!/bin/bash
# 三方依赖安全检查（**只读**）：按安全版本清单比对现场实际版本，输出问题清单 + 处理建议。
#
# 处置口径（2026-11-16 定稿，写死在输出里）：
#   - 中间件 / 独立依赖软件（mysql、xtrabackup、redis、nginx、tomcat、zk、kafka…）
#       → 工具可联网更新；无外网时用报告里给的中国大陆下载地址，由人执行。
#   - 代码内引用的 jar 包（含 fat jar 内嵌、WEB-INF/lib、插件 libs）
#       → 工具**不做任何替换/下载**，只记录问题，要求提单由研发更新。
#
# 本脚本保证：只执行读操作（find/unzip -l/--version/ps），只写报告文件，不改任何业务文件。
#
# 用法：
#   bash scan_secure_deps.sh local                 # 本机全量扫描，报告落到当前目录
#   bash scan_secure_deps.sh local --out /tmp/r    # 指定输出目录
#   bash scan_secure_deps.sh local --no-embedded   # 跳过 fat jar 内嵌检测（更快）
#   bash scan_secure_deps.sh local --dirs "/egova,/opt"
#   bash scan_secure_deps.sh ansible               # 逐台下发执行（结果留在各机）
# 返回码：0=无高危；1=存在需处理项；2=清单缺失；3=参数错误
set -u
_cur_shell_path=$0
_cur_shell_name=${_cur_shell_path##*/}
_cur_shell_dir=${_cur_shell_path%/*}
if [ "${_cur_shell_name}" == "${_cur_shell_dir}" ];then
    _cur_shell_dir=$(pwd)
fi
FLAT="${SECURE_VERSIONS_FLAT:-${_cur_shell_dir}/conf/secure-versions.flat}"

SCAN_DIRS="/egova /opt /home /data /usr/local/app /app /srv"
OUT_DIR="$(pwd)"
DO_EMBEDDED=1
EMBED_MIN_MB=10
EMBED_MAX_FILES=200

# ---------- 版本工具（与 query_secure_version.sh 同口径） ----------
ver_lt() {
    local v1=$1 v2=$2
    [ "$v1" == "$v2" ] && return 1
    local IFS='.-'
    local -a a1=($v1) a2=($v2)
    local i s1 s2 n=${#a1[@]}
    [ ${#a2[@]} -gt $n ] && n=${#a2[@]}
    for ((i=0; i<n; i++)); do
        s1=${a1[$i]:-}; s2=${a2[$i]:-}
        [ -z "$s1" ] && [ -z "$s2" ] && continue
        if [ -z "$s1" ]; then [[ "$s2" =~ ^[0-9]+$ ]] && return 0; continue; fi
        if [ -z "$s2" ]; then [[ "$s1" =~ ^[0-9]+$ ]] && return 1; continue; fi
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

# jar 文件名 -> (id, version)。先剥 classifier/-jre，再把版本段从 id 尾部剥掉。
norm_jar() {
    local f basename stripped ver
    f=${1##*/}
    basename=${f%.jar}
    stripped=$(echo "$basename" | sed -E 's/-(linux|windows|macosx|android)-(x86_64|aarch64|arm64|x86)$//; s/-(jre|jdk[0-9]*|android)$//')
    local try=$stripped
    for _ in 1 2 3 4 5 6; do
        if grep -qE "^(jar|software)\|${try}\|" "$FLAT" 2>/dev/null; then
            JAR_ID=$try
            ver=${stripped#${try}-}
            [ "$ver" == "$stripped" ] && ver=""
            ver=$(echo "$ver" | sed -E 's/-(linux|windows|macosx|android)-(x86_64|aarch64|arm64|x86)$//')
            JAR_VER=$ver
            return 0
        fi
        [[ "$try" != *-* ]] && break
        try=${try%-*}
    done
    JAR_ID=""; JAR_VER=""
    return 1
}

secure_of() { grep -m1 -E "^(jar|software)\|$1\|" "$FLAT" 2>/dev/null | cut -d'|' -f3; }
status_of() { grep -m1 -E "^(jar|software)\|$1\|" "$FLAT" 2>/dev/null | cut -d'|' -f8; }
update_of() { grep -m1 -E "^(jar|software)\|$1\|" "$FLAT" 2>/dev/null | cut -d'|' -f7; }
download_of() { grep -m1 -E "^(jar|software)\|$1\|" "$FLAT" 2>/dev/null | cut -d'|' -f6; }

# ---------- 结果集合 ----------
MD_LINES=""     # 报告正文
CSV_LINES=""    # 明细
N_HIGH=0; N_MID=0; N_OK=0; N_UNK=0

esc_csv() { echo "$1" | tr -d '\r\n' | sed 's/"/""/g'; }

add_row() { # 类别 组件 现版本 安全版本 判定 处置 位置
    local cat=$1 comp=$2 cur=$3 safe=$4 verdict=$5 action=$6 loc=$7
    MD_LINES="${MD_LINES}| ${cat} | ${comp} | ${cur} | ${safe} | ${verdict} | ${action} | ${loc} |
"
    CSV_LINES="${CSV_LINES}\"${cat}\",\"$(esc_csv "$comp")\",\"$(esc_csv "$cur")\",\"$(esc_csv "$safe")\",\"${verdict}\",\"$(esc_csv "$action")\",\"$(esc_csv "$loc")\"
"
    case "$verdict" in
        *高危*|*低于*) N_HIGH=$((N_HIGH+1)) ;;
        *待定*|*无法判定*|*待复核*) N_UNK=$((N_UNK+1)) ;;
        *无可用*) N_HIGH=$((N_HIGH+1)) ;;
        OK) N_OK=$((N_OK+1)) ;;
        *) N_MID=$((N_MID+1)) ;;
    esac
}

# 判定单个 jar（只读）
judge_jar() {
    local path=$1 origin=$2
    norm_jar "$path" || return 1
    local id=$JAR_ID ver=$JAR_VER safe st
    [ -z "$id" ] && return 1
    safe=$(secure_of "$id"); st=$(status_of "$id")
    if [ -z "$ver" ]; then
        add_row "jar" "$id" "未知" "${safe:-（待定）}" "无法判定" "提单研发确认版本后更新" "$origin"
        return 0
    fi
    if [ -z "$safe" ]; then
        add_row "jar" "$id" "$ver" "无安全版本" "无可用安全版本（${st}）" "提单研发：按清单更新方式迁移或接受风险" "$origin"
    elif ver_lt "$ver" "$safe"; then
        add_row "jar" "$id" "$ver" "$safe" "高危-低于安全版本" "提单研发更新（工具不替换）" "$origin"
    else
        add_row "jar" "$id" "$ver" "$safe" "OK" "无需处理" "$origin"
    fi
    return 0
}

# ---------- 1) 独立 jar ----------
scan_standalone_jars() {
    local d f
    for d in $SCAN_DIRS; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            judge_jar "$f" "$f"
        done < <(find "$d" -name "*.jar" -type f 2>/dev/null | grep -v "/docker/overlay2/.*/diff/" | head -n 4000)
    done
}

# ---------- 2) fat jar / exploded 内嵌 jar ----------
scan_embedded_jars() {
    [ "$DO_EMBEDDED" = "1" ] || return 0
    command -v unzip >/dev/null 2>&1 || { echo "提示: 未装 unzip，跳过内嵌检测" >&2; return 0; }
    local d f n=0 inner
    for d in $SCAN_DIRS; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            n=$((n+1))
            [ $n -gt $EMBED_MAX_FILES ] && return 0
            while IFS= read -r inner; do
                [ -z "$inner" ] && continue
                judge_jar "$inner" "${f}!/$(basename "$inner")"
            done < <(unzip -l "$f" 2>/dev/null | grep -Eo "BOOT-INF/lib/[^ /]+\.jar|WEB-INF/lib/[^ /]+\.jar" | sort -u)
        done < <(find "$d" -name "*.jar" -type f -size +${EMBED_MIN_MB}M 2>/dev/null | grep -v "/docker/overlay2/.*/diff/" | head -n 400)
    done
}

# ---------- 3) 中间件 / 独立依赖软件 ----------
sw_ver() { # 组件 现版本 位置（安全版本/判定自动取清单）
    local comp=$1 cur=$2 loc=$3 safe st action
    safe=$(secure_of "$comp"); st=$(status_of "$comp")
    if [ -z "$cur" ]; then
        add_row "软件" "$comp" "未检测到" "${safe:-（待定）}" "无法判定" "手工核实安装位置与版本" "$loc"
        return
    fi
    if [ -z "$safe" ]; then
        if [ "$st" == "待建" ] || [ -z "$st" ]; then
            add_row "软件" "$comp" "$cur" "（清单待建）" "待复核" "清单尚未定基线，先登记版本" "$loc"
        else
            add_row "软件" "$comp" "$cur" "无安全版本" "无可用安全版本（${st}）" "按清单更新方式迁移/接受风险" "$loc"
        fi
        return
    fi
    # 软件版本可能带后缀，只取版本号；secure 支持“各线最小安全版本”列表（如 3.8.8 / 3.9.7），
    # 按当前版本的大版本线（major.minor）取对应目标，取不到则用整体最小值。
    local cur_num safe_num tgt line_ver
    cur_num=$(echo "$cur" | grep -Eo '[0-9]+(\.[0-9]+)*[A-Za-z0-9.\-]*' | head -1)
    if [ -z "$cur_num" ]; then
        add_row "软件" "$comp" "$cur" "$safe" "待复核" "人工确认版本口径" "$loc"
        return
    fi
    local cur_line=$(echo "$cur_num" | grep -Eo '^[0-9]+\.[0-9]+')
    local cur_major=$(echo "$cur_num" | grep -Eo '^[0-9]+')
    local alt_list=$(echo "$safe" | grep -Eo '[0-9]+(\.[0-9]+)*[A-Za-z0-9.\-]*')
    tgt=""
    # 1) 同大版本线（major.minor）优先
    for line_ver in $alt_list; do
        if [ -n "$cur_line" ] && echo "$line_ver" | grep -qE "^${cur_line}(\.|-[A-Za-z]|$)"; then
            tgt=$line_ver; break
        fi
    done
    # 2) 退到同大版本（major），取该大版本下最小安全版本
    if [ -z "$tgt" ]; then
        for line_ver in $alt_list; do
            if echo "$line_ver" | grep -qE "^${cur_major}(\.|-[A-Za-z]|$)"; then
                if [ -z "$tgt" ] || ver_lt "$line_ver" "$tgt"; then tgt=$line_ver; fi
            fi
        done
    fi
    # 3) 再退到整体最小安全版本
    if [ -z "$tgt" ]; then
        for line_ver in $alt_list; do
            if [ -z "$tgt" ] || ver_lt "$line_ver" "$tgt"; then tgt=$line_ver; fi
        done
    fi
    safe_num=$tgt
    if [ -z "$safe_num" ]; then
        add_row "软件" "$comp" "$cur" "$safe" "待复核" "人工确认版本口径" "$loc"
    elif ver_lt "$cur_num" "$safe_num"; then
        add_row "软件" "$comp" "$cur" "$safe（本线需≥$safe_num）" "高危-低于安全版本" "可联网更新/用报告内国内地址人工升级" "$loc"
    else
        add_row "软件" "$comp" "$cur" "$safe（本线需≥$safe_num）" "OK" "无需处理" "$loc"
    fi
}

scan_software() {
    local v loc
    # MySQL
    loc=$(command -v mysqld 2>/dev/null); v=""
    [ -n "$loc" ] && v=$("$loc" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -z "$v" ] && v=$(mysql --version 2>/dev/null | grep -Eo 'Distrib [0-9.]+' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -z "$v" ] && { loc=$(docker ps --format '{{.Image}}' 2>/dev/null | grep -i mysql | head -1); [ -n "$loc" ] && v=$(echo "$loc" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1); }
    sw_ver mysql "$v" "${loc:-未找到}"

    # Redis（进程/容器/客户端）
    loc=$(command -v redis-server 2>/dev/null); v=""
    [ -n "$loc" ] && v=$(redis-server -v 2>/dev/null | grep -Eo 'v=[0-9.]+' | cut -d= -f2)
    if [ -z "$v" ]; then
        local port
        for port in 6379 6380 6381; do
            v=$(redis-cli -p $port info server 2>/dev/null | grep -E '^redis_version:' | tr -d '\r' | cut -d: -f2)
            [ -n "$v" ] && { loc="redis-cli -p $port"; break; }
        done
    fi
    [ -z "$v" ] && { loc=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -i redis | head -1); [ -n "$loc" ] && v=$(echo "$loc" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1); }
    sw_ver redis "$v" "${loc:-未找到}"

    # Percona XtraBackup
    loc=$(command -v xtrabackup 2>/dev/null); v=""
    [ -n "$loc" ] && v=$("$loc" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+-[0-9]+' | head -1)
    [ -z "$v" ] && { loc="rpm -qa percona-xtrabackup"; v=$(rpm -qa 2>/dev/null | grep -i xtrabackup | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1); }
    sw_ver xtrabackup "$v" "${loc:-未找到}"

    # Tomcat
    loc=""; v=""
    local cj=$(find /egova /opt /usr/local -maxdepth 6 -name "catalina.jar" 2>/dev/null | head -1)
    if [ -n "$cj" ]; then
        v=$(unzip -p "$cj" META-INF/MANIFEST.MF 2>/dev/null | grep -i Implementation-Version | head -1 | cut -d: -f2 | tr -d ' \r')
        loc="$cj"
    fi
    sw_ver tomcat "$v" "${loc:-未找到}"

    # Nginx / OpenResty
    loc=$(command -v openresty 2>/dev/null || echo /usr/local/openresty/nginx/sbin/nginx)
    v=""
    if [ -x "$loc" ]; then
        v=$("$loc" -v 2>&1 | grep -Eo '(openresty|nginx)/[0-9.]+' | head -1)
        [ -n "$v" ] && case "$v" in openresty/*) sw_ver openresty "${v#openresty/}" "$loc" ;; *) sw_ver nginx "${v#nginx/}" "$loc" ;; esac
    fi
    [ -z "$v" ] && sw_ver nginx "" "未找到 nginx/openresty"

    # ZooKeeper：优先按运行进程定位实际安装目录，再用 lib 内 jar 取版本（目录名常与运行版本不一致）
    loc=""; v=""
    local zkpid zkhome
    zkpid=$(ps -ef 2>/dev/null | grep -i "org.apache.zookeeper.server" | grep -v grep | awk '{print $2}' | head -1)
    if [ -n "$zkpid" ]; then
        zkhome=$(tr '\0' '\n' < /proc/$zkpid/cmdline 2>/dev/null | grep -E "zookeeper.*\.jar" | head -1)
        [ -n "$zkhome" ] && loc="pid=$zkpid $zkhome"
    fi
    [ -z "$loc" ] && loc=$(ls -d /egova/zookeeper_* /egova/zookeeper* /opt/zookeeper* /usr/local/zookeeper* 2>/dev/null | head -1)
    if [ -n "$loc" ]; then
        local zd=$(echo "$loc" | grep -oE "/[^ ]*" | head -1)
        v=$(find "$zd" -maxdepth 3 -name "zookeeper-[0-9]*.jar" 2>/dev/null | head -1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+')
        [ -z "$v" ] && v=$(echo "$zd" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    sw_ver zookeeper "$v" "$(echo "${loc:-未找到}" | cut -c1-80)"

    # Kafka：目录名不一定带版本，从 libs/kafka_*.jar 取
    loc=$(ls -d /egova/kafka* /opt/kafka* /usr/local/kafka* 2>/dev/null | head -1); v=""
    if [ -n "$loc" ]; then
        v=$(find "$loc/libs" -maxdepth 1 -name "kafka_2.*-*.jar" 2>/dev/null | head -1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [ -z "$v" ] && v=$(echo "$loc" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    sw_ver kafka "$v" "${loc:-未找到}"

    # Elasticsearch
    loc=$(ls -d /egova/elasticsearch* /opt/elasticsearch* /usr/share/elasticsearch 2>/dev/null | head -1); v=""
    [ -n "$loc" ] && v=$(echo "$loc" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -z "$v" ] && { v=$(curl -s --max-time 3 -k https://127.0.0.1:9200 2>/dev/null | grep -Eo '"number" *: *"[0-9.]+"' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1); [ -n "$v" ] && loc="https://127.0.0.1:9200"; }
    sw_ver elasticsearch "$v" "${loc:-未找到}"

    # Nacos：可能是 docker 部署（镜像名带版本），也可能是解压包（target/nacos-server.jar）
    loc=""; v=""
    local nimg=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -i nacos | head -1)
    if [ -n "$nimg" ]; then
        v=$(echo "$nimg" | grep -Eo 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//')
        loc="docker: $nimg"
    fi
    if [ -z "$v" ]; then
        loc=$(ls -d /egova/nacos* /opt/nacos* 2>/dev/null | head -1)
        if [ -n "$loc" ]; then
            local nj=$(find "$loc" -maxdepth 3 -name "nacos-server*.jar" 2>/dev/null | head -1)
            if [ -n "$nj" ]; then
                v=$(unzip -p "$nj" META-INF/MANIFEST.MF 2>/dev/null | grep -i 'Implementation-Version' | head -1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+')
                [ -z "$v" ] && v=$(basename "$nj" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+')
                loc="$nj"
            fi
            [ -z "$v" ] && v=$(echo "$loc" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        fi
    fi
    sw_ver nacos "$v" "$(echo "${loc:-未找到}" | cut -c1-80)"

    # RabbitMQ
    loc=$(command -v rabbitmqctl 2>/dev/null); v=""
    [ -n "$loc" ] && v=$(rabbitmqctl version 2>/dev/null | tr -d '\r' | head -1)
    sw_ver rabbitmq "$v" "${loc:-未找到}"

    # OpenSSL
    loc=$(command -v openssl 2>/dev/null); v=""
    [ -n "$loc" ] && v=$("$loc" version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+[a-z]*' | head -1)
    sw_ver openssl "$v" "${loc:-未找到}"

    # JDK
    loc=$(command -v java 2>/dev/null); v=""
    [ -n "$loc" ] && v=$(java -version 2>&1 | grep -Eo '"[0-9]+\.[0-9]+\.[0-9_]+"' | tr -d '"' | head -1)
    sw_ver jdk8 "$v" "${loc:-未找到}"

    # Python
    loc=$(command -v python3 2>/dev/null || command -v python 2>/dev/null); v=""
    [ -n "$loc" ] && v=$("$loc" --version 2>&1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    sw_ver python "$v" "${loc:-未找到}"
}

# ---------- 报告 ----------
write_report() {
    local ts host md csv
    ts=$(date +%Y%m%d_%H%M%S)
    host=$(hostname)
    md="$OUT_DIR/secure-deps-${host}-${ts}.md"
    csv="$OUT_DIR/secure-deps-${host}-${ts}.csv"
    mkdir -p "$OUT_DIR" || return 1
    {
        echo "# 三方依赖安全检查报告"
        echo
        echo "- 主机：${host}（$(hostname -I 2>/dev/null | awk '{print $1}')）"
        echo "- 时间：$(date '+%Y-%m-%d %H:%M:%S')"
        echo "- 清单：${FLAT}（$(grep -vc '^#' "$FLAT" 2>/dev/null) 条）"
        echo "- 扫描目录：${SCAN_DIRS}"
        echo "- 结论：高危/需处理 **${N_HIGH}** 项，待复核 ${N_UNK} 项，正常 ${N_OK} 项，其他 ${N_MID} 项"
        echo
        echo "## 处置口径"
        echo
        echo "- **本工具只做检测与登记，不修改任何业务文件、不替换任何 jar、不重启服务。**"
        echo "- 中间件 / 独立依赖软件（mysql、xtrabackup、redis、nginx、tomcat、zk、kafka…）：可联网更新；无外网时用本报告给出的中国大陆下载地址，由人执行升级。"
        echo "- 代码内引用的 jar 包（含 fat jar 内嵌、WEB-INF/lib、插件 libs）：**要求提单由研发更新**，工具不下载不替换。"
        echo
        echo "## 问题清单"
        echo
        echo "| 类别 | 组件 | 当前版本 | 安全版本 | 判定 | 建议处置 | 位置 |"
        echo "|---|---|---|---|---|---|---|"
        printf '%s' "$MD_LINES"
        echo
        echo "## 附：需升级的中间件下载地址（中国大陆可访问，按序优先）"
        echo
        echo '```'
        # 仅列出判定为需处理的软件类条目
        printf '%s' "$CSV_LINES" | awk -F'","' '$1=="\"软件" && $5 ~ /低于|无可用/ {print $2}' | tr -d '"' | sort -u | while read -r c; do
            [ -z "$c" ] && continue
            urls=$(download_of "$c")
            [ -z "$urls" ] && { echo "[$c] 清单未登记下载地址，请联系厂商/内网制品库"; continue; }
            echo "[$c] $urls"
        done
        echo '```'
        echo
        echo "## 附：需提单的 jar 清单（去重，按组件）"
        echo
        echo '```'
        printf '%s' "$CSV_LINES" | awk -F'","' '$1=="\"jar" && $5 !~ /OK/ {print $2"  (现 "$3" -> 安全 "$4")"}' | tr -d '"' | sort -u
        echo '```'
        echo
        echo "> 生成方式：\`bash scan_secure_deps.sh local\`。本报告为只读产物，可直接作为问题清单与提单依据。"
    } > "$md"
    {
        echo "类别,组件,当前版本,安全版本,判定,建议处置,位置"
        printf '%s' "$CSV_LINES"
    } > "$csv"
    echo "报告已生成："
    echo "  $md"
    echo "  $csv"
}

main() {
    [ -f "$FLAT" ] || { echo "清单缺失: $FLAT（先跑 sync_inventory.py gen 或 export）"; exit 2; }
    local mode=${1:-}; shift || true
    case "$mode" in
        local)
            while [ $# -gt 0 ]; do
                case "$1" in
                    --out) OUT_DIR=$2; shift 2 ;;
                    --dirs) SCAN_DIRS=$(echo "$2" | tr ',' ' '); shift 2 ;;
                    --no-embedded) DO_EMBEDDED=0; shift ;;
                    *) echo "未知参数: $1"; exit 3 ;;
                esac
            done
            echo "== 三方依赖安全检查（只读，不修改任何文件） =="
            echo "扫描目录: $SCAN_DIRS"
            scan_software
            echo "已检测中间件/软件版本，开始扫描 jar …"
            scan_standalone_jars
            echo "独立 jar 扫描完成，开始检测内嵌 jar …"
            scan_embedded_jars
            write_report
            [ $N_HIGH -gt 0 ] && exit 1
            exit 0
            ;;
        ansible)
            command -v ansible >/dev/null 2>&1 || { echo "未找到 ansible"; exit 3; }
            ansible all -m file -a "name=/tmp/toolbox/sec_deps/conf state=directory"
            ansible all -m copy -a "src=${_cur_shell_path} dest=/tmp/toolbox/sec_deps/scan_secure_deps.sh mode=0755"
            ansible all -m copy -a "src=${FLAT} dest=/tmp/toolbox/sec_deps/conf/secure-versions.flat mode=0644"
            ansible all -m shell -a "cd /tmp/toolbox/sec_deps && bash scan_secure_deps.sh local --out /tmp/toolbox/sec_deps"
            echo "各机报告位于 /tmp/toolbox/sec_deps/secure-deps-*.md，请回收汇总"
            exit 0
            ;;
        *)
            sed -n '2,25p' "$0"
            exit 3
            ;;
    esac
}

function support_multi_mode(){ echo 1; }
_is_sourced() {
    [ "${#FUNCNAME[@]}" -ge 2 ] && [ "${FUNCNAME[0]}" = '_is_sourced' ] && [ "${FUNCNAME[1]}" = 'source' ]
}
if ! _is_sourced; then main "$@"; fi
