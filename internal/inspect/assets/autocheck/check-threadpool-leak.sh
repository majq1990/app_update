#!/bin/bash
#
# 线程池泄漏 / 老代码风险检查
# --------------------------------------------------
# 目标：检查 java 进程中是否存在 "线程池未释放"+"ThreadLocal 未清理" 的老代码漏洞模式
# 思路：对每个 java 进程跑 jstack + jmap -histo
#   - jstack：统计线程池泄漏的直接信号（默认命名的 pool-N-thread-N 数量、阻塞在 ThreadPoolExecutor.getTask 的线程数）
#   - jmap -histo：统计 ThreadLocalMap 实例数和字节占用，作为放大器信号
#
# 阈值参考：20260615 福州网格化项目复盘（133 节点）
#   现场：544 线程 / 501 个 pool-N-thread-1 / ThreadLocalMap 保留 2.97 GB
#   本脚本阈值取现场值的 1/2 ~ 1/5，留缓冲防误报
# --------------------------------------------------

set -u
# 不要 set -e：jstack/jmap 偶发会失败，需要容错继续

# ---------- 阈值（绝对值，可后续提取为 ansible vars）----------
THREAD_POOL_DEFAULT_NAMED_MAX=100       # pool-N-thread-N（默认线程工厂命名）数量阈值
THREAD_BLOCKED_IN_GETTASK_MAX=50        # 阻塞在 ThreadPoolExecutor.getTask 的线程数阈值
THREAD_TOTAL_MAX=800                    # 单进程总线程数阈值
THREADLOCAL_MAP_INSTANCES_MAX=500       # ThreadLocal$ThreadLocalMap 实例数阈值
THREADLOCAL_MAP_BYTES_MAX=524288000     # ThreadLocalMap 占用字节阈值（500 MB）

# ---------- 工具函数 ----------
# JSON 转义（双引号 + 反斜杠，避免破坏 JSON 结构）
json_escape() {
    local input="$1"
    input="${input//\\/\\\\}"
    input="${input//\"/\\\"}"
    echo -n "$input"
}

# 读取 java 进程的 JDK 路径（用于挑选同源 jstack/jmap）
# 现场约定：/proc/<pid>/exe 是 java 可执行文件，readlink 后跳到 java，dirname 就是 bin 的上一级
get_java_home() {
    local pid=$1
    local java_bin
    java_bin=$(readlink "/proc/${pid}/exe" 2>/dev/null) || return 1
    # 形如 /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.412.b08-2.el8_10.x86_64/jre/bin/java
    # 也可能没有 jre 段。需要回退到上一级目录，直到找到 bin/jstack 同级为止
    local dir
    dir=$(dirname "$java_bin")  # .../bin
    while [ "$dir" != "/" ] && [ ! -x "${dir}/jstack" ]; do
        dir=$(dirname "$dir")
    done
    if [ -x "${dir}/jstack" ]; then
        echo "$dir"
        return 0
    fi
    # 回退：使用 PATH 中的 jstack（如果存在），这种情况不去校验版本
    local fallback
    fallback=$(command -v jstack 2>/dev/null) || return 1
    dirname "$(dirname "$fallback")"
}

# 获取 java 进程启动时间和主类（启发式，从 /proc/<pid>/cmdline 提取）
get_proc_info() {
    local pid=$1
    local cmdline_file="/proc/${pid}/cmdline"
    [ -r "$cmdline_file" ] || { echo "|"; return; }
    # cmdline 是 NUL 分隔，转成空格
    local cmd
    cmd=$(tr '\0' ' ' < "$cmdline_file" 2>/dev/null)
    # 启动时间
    local start_time
    start_time=$(stat -c %y "/proc/${pid}" 2>/dev/null | cut -d'.' -f1)
    echo "${start_time}|${cmd}"
}

# 对单个 PID 执行检查
# 输出 6 行字段到 stdout（用 \x1f 分隔，单行写入避免转义噩梦）
#   field1: process_basic_json（"启动时间|主类"）
#   field2: pool_metrics_json（线程池指标）
#   field3: histo_metrics_json（jmap histo 指标）
#   field4: stack_status（OK/SKIP/FAIL）
#   field5: histo_status（OK/SKIP/FAIL）
#   field6: error_message
check_one_pid() {
    local pid=$1
    local jhome
    jhome=$(get_java_home "$pid") || jhome=""
    local jstack_bin="${jhome:+${jhome}/}jstack"
    local jmap_bin="${jhome:+${jhome}/}jmap"

    # 进程信息
    local proc_info
    proc_info=$(get_proc_info "$pid")
    local start_time="${proc_info%%|*}"
    local cmdline="${proc_info#*|}"
    # 主类启发式：从 cmdline token 序列中跳过 java 二进制和所有 JVM 启动选项及其值
    # 用 while + case 实现，避免 awk 状态机的边界 bug
    local main_class=""
    if [ -n "$cmdline" ]; then
        local -a _tokens
        IFS=' ' read -r -a _tokens <<< "$cmdline"
        local _i=0
        # 跳过 java 二进制（cmdline[0]）
        if [ ${#_tokens[@]} -gt 0 ] && { [ "${_tokens[0]##*/}" = "java" ] || [ "${_tokens[0]}" = "java" ]; }; then
            _i=1
        fi
        while [ $_i -lt ${#_tokens[@]} ]; do
            local _tok="${_tokens[$_i]}"
            # 跳过 %p/%t 等占位符 token
            if [[ "$_tok" =~ ^%[a-zA-Z]+ ]]; then
                _i=$((_i+1)); continue
            fi
            if [[ "$_tok" == -* ]]; then
                case "$_tok" in
                    -jar)
                        # jar 模式：返回 jar 文件 basename（启发式拿不到 main class 全限定名）
                        if [ $((_i+1)) -lt ${#_tokens[@]} ]; then
                            local _jar="${_tokens[$((_i+1))]}"
                            main_class="${_jar##*/}"
                            break
                        fi
                        _i=$((_i+2)); continue
                        ;;
                    -cp|-classpath|-modulepath|-m|-add-modules|-limit-modules|-source|-target|-system)
                        # 显式带值选项：跳过值
                        _i=$((_i+2)); continue
                        ;;
                    *)
                        # 其他 - 开头的（-Dx=y、-Xmx4g、-Xloggc:f）：整体一个 token
                        _i=$((_i+1)); continue
                        ;;
                esac
            fi
            # 非选项 token：作为主类候选
            main_class="$_tok"
            break
        done
    fi
    # 解析 tomcat home 路径（从 -Dcatalina.base= 或 -Dcatalina.home= 提取）
    local tomcat_home=""
    if [ -n "$cmdline" ]; then
        # 优先从 -Dcatalina.base= 提取
        tomcat_home=$(echo "$cmdline" | grep -oP '(?<=-Dcatalina\.base=)\S+' | head -1)
        # 如果没有，从 -Dcatalina.home= 提取
        if [ -z "$tomcat_home" ]; then
            tomcat_home=$(echo "$cmdline" | grep -oP '(?<=-Dcatalina\.home=)\S+' | head -1)
        fi
    fi
    # 如果没有找到 tomcat home，使用主类作为 fallback
    if [ -z "$tomcat_home" ]; then
        tomcat_home="$main_class"
    fi

    # 截断路径，避免表格爆行
    local MAX_PATH_LEN=60
    if [ ${#tomcat_home} -gt $MAX_PATH_LEN ]; then
        tomcat_home="${tomcat_home:0:$MAX_PATH_LEN}..."
    fi

    local proc_basic
    proc_basic="\"01:PID\":\"$pid\",\"02:Tomcat Home\":\"$(json_escape "$tomcat_home")\""

    # ---------- jstack 检查 ----------
    local stack_status="SKIP"
    local pool_metrics=""
    local error_msg=""
    local jstack_out=""
    if [ -x "$jstack_bin" ]; then
        # -l 增强锁信息；不指定 -m 避免挂起
        jstack_out=$(timeout 15 "$jstack_bin" -l "$pid" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$jstack_out" ]; then
            stack_status="OK"
            local total_threads
            total_threads=$(echo "$jstack_out" | grep -cE '^"[^"]+" #' || true)
            # 默认命名线程池：pool-N-thread-M（JDK 默认 ThreadFactory 生成的名字）
            local pool_named
            pool_named=$(echo "$jstack_out" | grep -cE '^"pool-[0-9]+-thread-' || true)
            # 阻塞在 ThreadPoolExecutor.getTask / LinkedBlockingQueue.take 的线程
            local blocked_in_gettask
            blocked_in_gettask=$(echo "$jstack_out" | awk '
                /^"/ { in_thread=1; block=0; next }
                in_thread && /ThreadPoolExecutor\.getTask/ { block=1 }
                in_thread && /^\s*java\.lang\.Thread\.State:/ {
                    if (block && /WAITING/) count++
                    in_thread=0; block=0
                }
                END { print count+0 }
            ')
            # 已泄漏信号叠加分
            local leak_signals=""
            [ "$total_threads" -gt "$THREAD_TOTAL_MAX" ] && leak_signals="${leak_signals}总线程超限;"
            [ "$pool_named" -gt "$THREAD_POOL_DEFAULT_NAMED_MAX" ] && leak_signals="${leak_signals}默认命名线程池超限;"
            [ "$blocked_in_gettask" -gt "$THREAD_BLOCKED_IN_GETTASK_MAX" ] && leak_signals="${leak_signals}getTask阻塞线程超限;"

            pool_metrics="\"01:总线程数\":\"$total_threads\",\"02:默认命名线程池线程数\":\"$pool_named\",\"03:阻塞getTask线程数\":\"$blocked_in_gettask\",\"04:状态\":\"$stack_status\""
        else
            stack_status="FAIL"
            error_msg="jstack执行失败"
        fi
    else
        stack_status="FAIL"
        error_msg="${error_msg}未找到jstack;"
    fi

    # ---------- jmap -histo 检查 ----------
    local histo_status="SKIP"
    local histo_metrics=""
    if [ -x "$jmap_bin" ]; then
        # -histo:live 会触发 full GC，谨慎但现场 JDK 8 用这个能拿到活对象
        # 用 head -100 截断，避免大堆输出过长
        local jmap_out
        jmap_out=$(timeout 20 "$jmap_bin" -histo:live "$pid" 2>/dev/null | head -200)
        if [ $? -eq 0 ] && [ -n "$jmap_out" ]; then
            histo_status="OK"
            # 解析格式： num     #instances         #bytes  class name [ (module) ]
            # JDK 9+ 会附 (module) 后缀，先剥离再匹配
            # 注意保留前缀空白以维持 awk 字段号
            local clean_out
            clean_out=$(echo "$jmap_out" | sed -E 's/ \([a-zA-Z0-9_.@-]+\)$//')
            local tlm_inst tlm_bytes
            tlm_inst=$(echo "$clean_out" | awk '$NF == "java.lang.ThreadLocal$ThreadLocalMap" { print $2 }' | head -1)
            tlm_bytes=$(echo "$clean_out" | awk '$NF == "java.lang.ThreadLocal$ThreadLocalMap" { print $3 }' | head -1)

            # 空值补 0
            : "${tlm_inst:=0}" "${tlm_bytes:=0}"

            local histo_signals=""
            [ "$tlm_inst" -gt "$THREADLOCAL_MAP_INSTANCES_MAX" ] && histo_signals="${histo_signals}ThreadLocalMap实例数超限;"
            [ "$tlm_bytes" -gt "$THREADLOCAL_MAP_BYTES_MAX" ] && histo_signals="${histo_signals}ThreadLocalMap占用超限;"

            histo_metrics="\"01:ThreadLocalMap实例数\":\"$tlm_inst\",\"02:ThreadLocalMap占用字节\":\"$tlm_bytes\",\"03:状态\":\"$histo_status\""
        else
            histo_status="FAIL"
            error_msg="${error_msg}jmap执行失败;"
        fi
    else
        histo_status="FAIL"
        error_msg="${error_msg}未找到jmap;"
    fi

    # 整体检查状态
    local overall="健康"
    local result_msg=""
    
    # 收集所有问题
    [ -n "$leak_signals" ] && result_msg="${result_msg}${leak_signals}"
    [ -n "$histo_signals" ] && result_msg="${result_msg}${histo_signals}"
    [ -n "$error_msg" ] && result_msg="${result_msg}${error_msg}"
    
    # 如果有问题则标记为不健康
    [ -n "$result_msg" ] && overall="不健康:$(json_escape "$result_msg")"

    # 输出单行 JSON 片段（用 \x1f 拼接，便于后续 awk/while 解析）
    local proc_row
    proc_row="{${proc_basic},${pool_metrics},${histo_metrics},\"05:结果::WRAPDATA_ne__quot_健康_quot_\":\"$overall\"}"
    printf '%s\n' "$proc_row"
}

# ---------- 主流程 ----------
# 1) 抓 tomcat 进程列表（只查找包含 tomcat 的 java 进程）
# 使用 ps 而非遍历 /proc，更稳
java_pids=$(ps -ef | grep '[j]ava' | grep '[t]omcat' | awk '{print $2}' | sort -u)

if [ -z "$java_pids" ]; then
    # 没有 java 进程也要输出合法 JSON
    cat <<EOF
{
  "basic": {
    "01:tomcat进程数": "0",
    "02:风险进程数::WRAPDATA_gt__quot_0_quot_": "0"
  },
  "topics": {
    "01:Tomcat进程线程池与堆对象检查": [
      {
        "01:PID": "-",
        "02:Tomcat Home": "-",
        "03:总线程数::WRAPDATA_gt__quot_${THREAD_TOTAL_MAX}_quot_": "0",
        "04:默认命名线程池线程数::WRAPDATA_gt__quot_${THREAD_POOL_DEFAULT_NAMED_MAX}_quot_": "0",
        "05:阻塞getTask线程数::WRAPDATA_gt__quot_${THREAD_BLOCKED_IN_GETTASK_MAX}_quot_": "0",
        "06:ThreadLocalMap实例数::WRAPDATA_gt__quot_${THREADLOCAL_MAP_INSTANCES_MAX}_quot_": "0",
        "07:ThreadLocalMap占用字节::WRAPDATA_gt__quot_${THREADLOCAL_MAP_BYTES_MAX}_quot_": "0",
        "08:结果::WRAPDATA_ne__quot_健康_quot_": "健康"
      }
    ]
  }
}
EOF
    exit 0
fi

# 2) 逐个进程检查，收集所有 JSON 行
proc_rows=""
proc_count=0
abnormal_count=0
for pid in $java_pids; do
    # 进程可能已退出（僵尸或已回收）。僵尸进程 /proc/<pid>/cmdline 还能读但 exe 死链
    if [ ! -d "/proc/${pid}" ] || [ ! -r "/proc/${pid}/cmdline" ] || [ ! -e "/proc/${pid}/exe" ]; then
        continue
    fi
    row=$(check_one_pid "$pid")
    [ -z "$row" ] && continue
    if [ -z "$proc_rows" ]; then
        proc_rows="$row"
    else
        proc_rows="${proc_rows}
${row}"
    fi
    proc_count=$((proc_count + 1))
    # 提取结果状态 - 检查是否为不健康
    if echo "$row" | grep -qE '"08:结果(::[^"]*)?":"不健康'; then
        abnormal_count=$((abnormal_count + 1))
    fi
done

# 3) 组装最终 JSON
# basic 段：汇总
# topics 段：每个进程一行，字段顺序由 key 排序决定，所以前面 key 都加 01:02: 前缀
# 注意：report 模板会把 topics[0] 的所有 key 当作表头，多进程数据列必须一致
# 行字段固定：01:PID 02:Tomcat Home 03:总线程数 04:默认命名线程池线程数 05:阻塞getTask线程数 06:ThreadLocalMap实例数 07:ThreadLocalMap占用字节 08:结果

# 重排每个 row 的字段到统一顺序
normalized_rows=""
while IFS= read -r row; do
    [ -z "$row" ] && continue
    # 解析原 row 重新组装（用 sed -n 提取每个字段，避免 subshell 开销）
    _pid=$(printf '%s' "$row" | sed -nE 's/.*"01:PID":"([0-9]+)".*/\1/p' | head -1)
    _cls=$(printf '%s' "$row" | sed -nE 's/.*"02:Tomcat Home":"([^"]*)".*/\1/p' | head -1)
    _total=$(printf '%s' "$row" | sed -nE 's/.*"01:总线程数":"([0-9]+)".*/\1/p' | head -1)
    _pool=$(printf '%s' "$row" | sed -nE 's/.*"02:默认命名线程池线程数":"([0-9]+)".*/\1/p' | head -1)
    _blk=$(printf '%s' "$row" | sed -nE 's/.*"03:阻塞getTask线程数":"([0-9]+)".*/\1/p' | head -1)
    _tlm_inst=$(printf '%s' "$row" | sed -nE 's/.*"01:ThreadLocalMap实例数":"([0-9]+)".*/\1/p' | head -1)
    _tlm_bytes=$(printf '%s' "$row" | sed -nE 's/.*"02:ThreadLocalMap占用字节":"([0-9]+)".*/\1/p' | head -1)
    _result=$(printf '%s' "$row" | sed -nE 's/.*"05:结果(::[^"]*)?":"([^"]*)".*/\2/p' | head -1)

    # 空值兜底
    : "${_total:=0}" "${_pool:=0}" "${_blk:=0}" "${_tlm_inst:=0}" "${_tlm_bytes:=0}" "${_result:=健康}"

    # 构造统一 schema 的行
    normalized_row="{\"01:PID\":\"$_pid\",\"02:Tomcat Home\":\"$_cls\",\"03:总线程数::WRAPDATA_gt__quot_${THREAD_TOTAL_MAX}_quot_\":\"$_total\",\"04:默认命名线程池线程数::WRAPDATA_gt__quot_${THREAD_POOL_DEFAULT_NAMED_MAX}_quot_\":\"$_pool\",\"05:阻塞getTask线程数::WRAPDATA_gt__quot_${THREAD_BLOCKED_IN_GETTASK_MAX}_quot_\":\"$_blk\",\"06:ThreadLocalMap实例数::WRAPDATA_gt__quot_${THREADLOCAL_MAP_INSTANCES_MAX}_quot_\":\"$_tlm_inst\",\"07:ThreadLocalMap占用字节::WRAPDATA_gt__quot_${THREADLOCAL_MAP_BYTES_MAX}_quot_\":\"$_tlm_bytes\",\"08:结果::WRAPDATA_ne__quot_健康_quot_\":\"$_result\"}"
    if [ -z "$normalized_rows" ]; then
        normalized_rows="$normalized_row"
    else
        normalized_rows="${normalized_rows},${normalized_row}"
    fi
done <<< "$proc_rows"

overall_status=$([ "$abnormal_count" -eq 0 ] && echo "YES" || echo "NO")

cat <<EOF
{
  "basic": {
    "01:tomcat进程数": "$proc_count",
    "02:风险进程数::WRAPDATA_gt__quot_0_quot_": "$abnormal_count"
  },
  "topics": {
    "01:Tomcat进程线程池与堆对象检查": [
$normalized_rows
    ]
  }
}
EOF

exit 0