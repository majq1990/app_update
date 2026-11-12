#!/usr/bin/env bash
###############################################################################
# check-kernel-cve.sh — 内核高危漏洞全兼容检查（多CVE、缓解感知、不强制重启升级）
#
# 覆盖（截至 2026-10，含 CISA KEV 在野利用项）：
#   CVE-2026-31431  algif_aead "Copy Fail" 本地提权        CVSS 7.8  PoC公开
#   CVE-2025-39964  AF_ALG 并发写竞态(容器逃逸/提权)        CVSS 7.8  KEV 在野利用
#   CVE-2025-39682  内核 kTLS rx 零长记录(远程)             CVSS 9.8  KEV 在野利用
#   CVE-2026-53266  ebtables SNAT ARP 越界写               CVSS 8.8  KEV 在野利用
#   CVE-2024-1086   nf_tables UAF 本地提权                 CVSS 7.8  KEV 公开exploit
#   io_uring 家族    CVE-2025-40047/40364/38730/21863/68317 反复出现的UAF提权
#
# 检测原则：
#   1. 纯本地探测，不开 AF_ALG/io_uring 等任何攻击面 socket
#   2. 三态结论：NOT_AFFECTED(版本范围外) / PATCHED(已修复) / MITIGATED(已缓解)
#      / VULNERABLE(暴露) / UNKNOWN
#   3. 缓解措施与漏洞共存属正常结论(MITIGATED)：cmdline/initcall 黑名单、
#      modprobe.d 黑名单、sysctl 运行时开关、业务规则缺失均认定为有效缓解，
#      不强制"必须升级内核重启"；缓解不可靠时明确标注 unreliable 及无需重启的补救命令
#
# 已知坑位（沿用原单CVE脚本结论）：
#   RHEL 系 algif_aead 常内建(CONFIG_CRYPTO_USER_API_AEAD=y)，modprobe.d 无效，
#   仅 initcall_blacklist=algif_aead_init(或 af_alg_init) 有效
#
# 用法:
#   ./check-kernel-cve.sh            人读报告(默认)
#   ./check-kernel-cve.sh --json     JSON 全量结果(ansible 管道用)
#   ./check-kernel-cve.sh --nagios   Nagios/NRPE 格式
#   ./check-kernel-cve.sh --zabbix   Zabbix 整数: 0=安全 1=存在漏洞 2=未知
#
# 退出码: 0=无暴露(已修复/已缓解/不受影响)  1=存在VULNERABLE  2=仅有UNKNOWN
#
# 测试辅助: 环境变量 CHECK_ROOT 可重定向 /proc /sys /etc /lib 根（离线自测用）
###############################################################################

set -uo pipefail

MODE="${1:---human}"
R="${CHECK_ROOT:-}"

# CHECK_KERNEL 可覆盖内核版本(离线自测/现场排查用), 默认取真实内核
KERNEL_FULL="${CHECK_KERNEL:-$(uname -r 2>/dev/null || echo unknown)}"
if [[ "$KERNEL_FULL" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    KERNEL_NUMERIC="${BASH_REMATCH[1]}"
else
    KERNEL_NUMERIC="0.0.0"
fi

DISTRO_ID=""; DISTRO_VER=""
if [[ -f "$R/etc/os-release" ]]; then
    # shellcheck disable=SC1091
    DISTRO_ID=$(. "$R/etc/os-release" 2>/dev/null; echo "${ID:-}")
    # shellcheck disable=SC1091
    DISTRO_VER=$(. "$R/etc/os-release" 2>/dev/null; echo "${VERSION_ID:-}")
fi
HOSTNAME=$(hostname -f 2>/dev/null || hostname)

ver_int() {
    local IFS='.'
    local v=($1)
    printf '%d%04d%04d' "${v[0]:-0}" "${v[1]:-0}" "${v[2]:-0}"
}
K=$(ver_int "$KERNEL_NUMERIC")

# ─── 通用探测（全部只读） ─────────────────────────────────────────────────────
module_loaded()   { [[ -d "$R/sys/module/$1" ]]; }
module_builtin()  {
    local bf="$R/lib/modules/$KERNEL_FULL/modules.builtin"
    [[ -f "$bf" ]] && grep -qs "$1" "$bf"
}
modprobe_blacklisted() {
    # 注意: 不能用 "grep | grep -q" 管道——上游 grep 会因 SIGPIPE 以141退出,
    # 在 set -o pipefail 下整体误判为未拉黑
    grep -qrhsE "(blacklist|install)[[:space:]]+$1([[:space:]]|$)" \
        "$R/etc/modprobe.d" "$R/lib/modprobe.d" 2>/dev/null
}
cmdline_has() { grep -qs "$1" "$R/proc/cmdline" 2>/dev/null; }
sysctl_val()  { [[ -f "$R/proc/sys/$1" ]] && cat "$R/proc/sys/$1" 2>/dev/null; }
have_cmd()    { command -v "$1" >/dev/null 2>&1; }

# 状态值: NOT_AFFECTED / PATCHED / MITIGATED / VULNERABLE / UNKNOWN
declare -a RES_CVE=() RES_NAME=() RES_CVSS=() RES_STATUS=() RES_DETAIL=()
N_RESULTS=0

add_result() {  # add_result <cve> <name> <cvss> <status> <detail>
    RES_CVE+=("$1"); RES_NAME+=("$2"); RES_CVSS+=("$3"); RES_STATUS+=("$4")
    RES_DETAIL+=("$5"); N_RESULTS=$((N_RESULTS+1))
}

# ─── CVE-2026-31431 algif_aead "Copy Fail" ───────────────────────────────────
check_31431() {
    local status="" detail=""
    local mit_cmdline=false mit_modprobe=false abs=false builtin=false
    cmdline_has "initcall_blacklist=algif_aead_init" && mit_cmdline=true
    cmdline_has "initcall_blacklist=af_alg_init" && mit_cmdline=true
    modprobe_blacklisted "algif_aead" && mit_modprobe=true
    module_loaded "algif_aead" || abs=true
    module_builtin "algif_aead" && builtin=true

    if (( K < $(ver_int "4.14.0") )); then
        status="NOT_AFFECTED"; detail="内核早于4.14(回归commit 72548b093ee3之前)"
    elif (( K >= $(ver_int "6.20.0") )) || (( K >= $(ver_int "6.19.12") )) || { (( K >= $(ver_int "6.18.22") )) && (( K < $(ver_int "6.19.0") )); }; then
        status="PATCHED"; detail="上游修复已包含(>=6.18.22/6.19.12/6.20)"
    elif $mit_cmdline; then
        status="MITIGATED"; detail="内核版本在受影响范围, 但 cmdline initcall_blacklist 已屏蔽 algif_aead/af_alg 初始化, 无需升级重启"
    elif $builtin; then
        status="VULNERABLE"; detail="algif_aead 内建于内核且无 cmdline 缓解, modprobe.d 黑名单无效; 建议: 维护窗口加 initcall_blacklist=algif_aead_init 重启, 或安排内核升级"
    elif $mit_modprobe && $abs; then
        status="MITIGATED"; detail="modprobe.d 已拉黑且模块未加载, 无需升级重启"
    elif $abs; then
        status="VULNERABLE"; detail="模块未加载但未拉黑, 本地用户触发 AF_ALG socket 可按需自动加载; 可立即缓解(无需重启): 配置 modprobe.d 黑名单"
    else
        status="VULNERABLE"; detail="模块已加载且无缓解; 可立即缓解(无需重启): modprobe -r algif_aead 并配置 modprobe.d 黑名单; 根治需升级内核"
    fi
    add_result "CVE-2026-31431" "Copy Fail-algif_aead本地提权" "7.8" "$status" "$detail"
}

# ─── CVE-2025-39964 AF_ALG 并发写竞态(KEV) ───────────────────────────────────
check_39964() {
    local status="" detail=""
    local af_cmdline=false af_black=false abs=false builtin=false
    cmdline_has "initcall_blacklist=af_alg_init" && af_cmdline=true
    modprobe_blacklisted "af_alg" && af_black=true
    module_loaded "af_alg" || abs=true
    module_builtin "af_alg" && builtin=true

    if $af_cmdline; then
        status="MITIGATED"; detail="cmdline initcall_blacklist=af_alg_init 已屏蔽整个 AF_ALG 接口, 无需升级重启"
    elif $builtin; then
        status="VULNERABLE"; detail="AF_ALG 内建于内核且未做 initcall 黑名单(KEV 在野利用); 建议: 维护窗口加 initcall_blacklist=af_alg_init 或升级内核"
    elif $af_black && $abs; then
        status="MITIGATED"; detail="af_alg 已拉黑且未加载, 无需升级重启"
    elif $abs; then
        status="VULNERABLE"; detail="af_alg 未加载但未拉黑, 可被按需自动加载; 可立即缓解(无需重启): modprobe.d 拉黑 af_alg"
    else
        status="VULNERABLE"; detail="AF_ALG 可用(KEV 在野利用); 可立即缓解(无需重启): modprobe -r af_alg 并拉黑; 根治需升级内核"
    fi
    add_result "CVE-2025-39964" "AF_ALG并发写竞态-提权/容器逃逸" "7.8" "$status" "$detail"
}

# ─── CVE-2025-39682 内核 kTLS rx(KEV, 9.8, 远程) ─────────────────────────────
check_39682() {
    local status="" detail=""
    local tls_black=false abs=false builtin=false loaded=false
    modprobe_blacklisted "tls" && tls_black=true
    module_loaded "tls" && loaded=true || abs=true
    module_builtin "tls" && builtin=true

    if (( K < $(ver_int "4.17.0") )); then
        status="NOT_AFFECTED"; detail="内核早于4.17, 无 kTLS rx 路径"
    elif (( K >= $(ver_int "6.16.4") )) || { (( K >= $(ver_int "6.12.44") )) && (( K < $(ver_int "6.13.0") )); } || { (( K >= $(ver_int "6.6.103") )) && (( K < $(ver_int "6.7.0") )); } || { (( K >= $(ver_int "6.1.149") )) && (( K < $(ver_int "6.2.0") )); }; then
        status="PATCHED"; detail="上游修复已包含(6.1.149/6.6.103/6.12.44/6.16.4)"
    elif $builtin; then
        status="VULNERABLE"; detail="tls 内建于内核(9.8高危, 可远程触发); 建议: 升级内核, 或确认无业务使用 kTLS 后评估发行版关闭 CONFIG_TLS"
    elif $loaded; then
        status="VULNERABLE"; detail="tls 模块已加载; 可立即缓解(无需重启): 确认无 kTLS 会话后 modprobe -r tls 并拉黑; 根治需升级内核"
    elif $tls_black; then
        status="MITIGATED"; detail="tls 已拉黑且未加载, 攻击面不可达, 无需升级重启"
    else
        status="VULNERABLE"; detail="tls 模块未加载但未拉黑, 可被 setsockopt 自动加载; 可立即缓解(无需重启): modprobe.d 拉黑 tls"
    fi
    add_result "CVE-2025-39682" "内核kTLS零长记录-远程" "9.8" "$status" "$detail"
}

# ─── CVE-2026-53266 ebtables SNAT(KEV, 8.8) ──────────────────────────────────
check_53266() {
    local status="" detail=""
    local snat_mod=false snat_rules=false
    module_loaded "ebtable_snat" && snat_mod=true
    if have_cmd ebtables; then
        ebtables -t nat -L 2>/dev/null | grep -qEi 'snat|arpreply' && snat_rules=true
    fi

    if ! $snat_mod && ! have_cmd ebtables; then
        status="NOT_AFFECTED"; detail="ebtables 用户态与内核模块均不存在, 攻击面不可达"
    elif ! $snat_rules; then
        status="MITIGATED"; detail="未配置 ebtables nat 表 SNAT/ARP 改写规则, 无需升级重启"
    else
        status="VULNERABLE"; detail="检测到 ebtables SNAT 类规则(KEV 在野利用); 可立即缓解(无需重启): 移除 nat 表 SNAT/ARP 改写规则或 modprobe -r ebtable_snat; 根治需升级内核"
    fi
    add_result "CVE-2026-53266" "ebtables SNAT越界写" "8.8" "$status" "$detail"
}

# ─── CVE-2024-1086 nf_tables UAF(KEV) ────────────────────────────────────────
check_1086() {
    local status="" detail=""
    local userns_off=false nft_black=false abs=false builtin=false
    local unpc maxns
    unpc=$(sysctl_val "kernel/unprivileged_userns_clone")
    maxns=$(sysctl_val "user/max_user_namespaces")
    [[ "${unpc:-1}" == "0" || "${maxns:-1}" == "0" ]] && userns_off=true
    modprobe_blacklisted "nf_tables" && nft_black=true
    module_loaded "nf_tables" || abs=true
    module_builtin "nf_tables" && builtin=true

    if (( K < $(ver_int "5.14.0") )); then
        status="NOT_AFFECTED"; detail="内核早于5.14, 不在受影响范围"
    elif (( K >= $(ver_int "6.7.3") )); then
        status="PATCHED"; detail="上游修复已包含(>=6.7.3)"
    elif $userns_off; then
        status="MITIGATED"; detail="非特权用户命名空间已禁用(kernel.unprivileged_userns_clone=0 或 user.max_user_namespaces=0), 常规提权路径不可达, 无需升级重启"
    elif $abs && ($nft_black || ! $builtin); then
        status="MITIGATED"; detail="nf_tables 未加载" $([ "$nft_black" = true ] && echo "且已拉黑") ", 无需升级重启"
    elif $builtin || $([ "$abs" = false ] && echo true || echo false); then
        status="VULNERABLE"; detail="nf_tables 可用且允许非特权 userns(公开exploit广泛); 可立即缓解(无需重启): sysctl -w user.max_user_namespaces=0(注意容器影响); 根治需升级内核"
    else
        status="VULNERABLE"; detail="nf_tables 可用且未做缓解; 可立即缓解(无需重启): 拉黑并卸载 nf_tables 或禁用非特权 userns"
    fi
    add_result "CVE-2024-1086" "nf_tables UAF本地提权" "7.8" "$status" "$detail"
}

# ─── io_uring 家族(CVE-2025-40047/40364/38730/21863/68317) ───────────────────
check_iouring() {
    local status="" detail=""
    local cves="CVE-2025-40047,CVE-2025-40364,CVE-2025-38730,CVE-2025-21863,CVE-2025-68317"
    local disabled="" abs=false builtin=false black=false
    disabled=$(sysctl_val "kernel/io_uring_disabled")
    module_loaded "io_uring" || abs=true
    module_builtin "io_uring" && builtin=true
    modprobe_blacklisted "io_uring" && black=true

    if (( K < $(ver_int "5.1.0") )); then
        status="NOT_AFFECTED"; detail="内核早于5.1, 无 io_uring"
    elif [[ "${disabled:-0}" == "2" || "${disabled:-0}" == "1" ]]; then
        status="MITIGATED"; detail="kernel.io_uring_disabled=${disabled} 已运行时禁用 io_uring, 无需升级重启"
    elif $builtin || ! $abs; then
        status="VULNERABLE"; detail="io_uring 可用(家族性UAF反复出现, 多个在野利用); 可立即缓解(无需重启): sysctl -w kernel.io_uring_disabled=2(注意影响使用io_uring的业务); 根治需升级内核"
    elif $abs && $black; then
        status="MITIGATED"; detail="io_uring 已拉黑且未加载, 无需升级重启"
    else
        status="VULNERABLE"; detail="io_uring 模块未加载但未拉黑且无运行时开关; 可立即缓解(无需重启): modprobe.d 拉黑 io_uring"
    fi
    add_result "io_uring家族" "$cves" "7.0+" "$status" "$detail"
}

check_31431
check_39964
check_39682
check_53266
check_1086
check_iouring

# ─── 汇总 ─────────────────────────────────────────────────────────────────────
VERDICT="PATCHED"; VULN_LIST=""; UNKNOWN_FLAG=false; MIT_FLAG=false; UNRELIABLE_FLAG=false
SVCOUNT=0
for ((i=0; i<N_RESULTS; i++)); do
    case "${RES_STATUS[$i]}" in
        VULNERABLE)
            VERDICT="VULNERABLE"
            VULN_LIST+="${RES_CVE[$i]} "
            SVCOUNT=$((SVCOUNT+1))
            ;;
        UNKNOWN) UNKNOWN_FLAG=true ;;
        MITIGATED) MIT_FLAG=true ;;
    esac
    [[ "${RES_STATUS[$i]}" == "MITIGATED" && "${RES_DETAIL[$i]}" == *未拉黑* ]] && UNRELIABLE_FLAG=true
done
[[ "$VERDICT" != "VULNERABLE" && "$UNKNOWN_FLAG" == true ]] && VERDICT="UNKNOWN"
[[ "$VERDICT" == "PATCHED" && "$MIT_FLAG" == true ]] && VERDICT="MITIGATED"
VULN_LIST=${VULN_LIST% }

MIT_NOTE=""
$MIT_FLAG && MIT_NOTE="部分漏洞已缓解; "
$UNRELIABLE_FLAG && MIT_NOTE+="存在缓解不完全的项, 详见明细; "

# 内核包信息(供应商 backport 参考用)
PKG_VER=""
if have_cmd rpm; then
    PKG_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' kernel 2>/dev/null | head -1)
    [[ "$PKG_VER" == package* ]] && PKG_VER=""
elif have_cmd dpkg; then
    PKG_VER=$(dpkg -l "linux-image-${KERNEL_FULL}" 2>/dev/null | awk '/^ii/{print $3; exit}')
fi

_exit_code() {
    case "$VERDICT" in
        PATCHED|MITIGATED|NOT_AFFECTED) echo 0 ;;
        VULNERABLE)                     echo 1 ;;
        *)                              echo 2 ;;
    esac
}

case "$MODE" in
    --nagios|--nrpe|--icinga)
        if [[ "$VERDICT" == "VULNERABLE" ]]; then
            echo "CRITICAL: kernel CVEs VULNERABLE: ${VULN_LIST} | kernel=${KERNEL_FULL}"
            exit 2
        elif [[ "$VERDICT" == "UNKNOWN" ]]; then
            echo "UNKNOWN: kernel CVE check incomplete | kernel=${KERNEL_FULL}"
            exit 3
        else
            echo "OK: kernel CVEs ${VERDICT} | kernel=${KERNEL_FULL}"
            exit 0
        fi
        ;;
    --zabbix)
        case "$VERDICT" in
            VULNERABLE) echo 1 ;;
            UNKNOWN)    echo 2 ;;
            *)          echo 0 ;;
        esac
        exit 0
        ;;
    --json)
        jstr() { printf '"%s"' "$1"; }
        jbool() { $1 && echo "true" || echo "false"; }
        # 任一"暴露且完全无缓解"则缓解不可靠
        OVERALL_RELIABLE=true
        for ((i=0; i<N_RESULTS; i++)); do
            [[ "${RES_STATUS[$i]}" == "VULNERABLE" ]] && OVERALL_RELIABLE=false
        done
        out="{"
        out+="\"hostname\": $(jstr "$HOSTNAME"),"
        out+="\"kernel\": $(jstr "$KERNEL_FULL"),"
        out+="\"kernel_numeric\": $(jstr "$KERNEL_NUMERIC"),"
        out+="\"distro_id\": $(jstr "$DISTRO_ID"),"
        out+="\"distro_ver\": $(jstr "$DISTRO_VER"),"
        out+="\"cve\": $(jstr "CVE-2026-31431,CVE-2025-39964,CVE-2025-39682,CVE-2026-53266,CVE-2024-1086,io_uring家族"),"
        out+="\"cve_count\": $N_RESULTS,"
        out+="\"vulnerable_count\": $SVCOUNT,"
        out+="\"vulnerable_cves\": $(jstr "$VULN_LIST"),"
        out+="\"kernel_vuln_status\": $(jstr "$VERDICT"),"
        out+="\"pkg_check\": $(jstr "${PKG_VER:+found}"),"
        out+="\"pkg_ver\": $(jstr "$PKG_VER"),"
        out+="\"mitigated\": $(jbool "$MIT_FLAG"),"
        out+="\"mitigation_reliable\": $(jbool "$OVERALL_RELIABLE"),"
        out+="\"mitigation_note\": $(jstr "$MIT_NOTE"),"
        out+="\"verdict\": $(jstr "$VERDICT"),"
        out+="\"results\": ["
        for ((i=0; i<N_RESULTS; i++)); do
            (( i > 0 )) && out+=","
            out+="{\"cve\": $(jstr "${RES_CVE[$i]}"),"
            out+="\"name\": $(jstr "${RES_NAME[$i]}"),"
            out+="\"cvss\": $(jstr "${RES_CVSS[$i]}"),"
            out+="\"status\": $(jstr "${RES_STATUS[$i]}"),"
            out+="\"detail\": $(jstr "${RES_DETAIL[$i]}")}"
        done
        out+="]}"
        printf '%s\n' "$out"
        exit "$(_exit_code)"
        ;;
    *)
        echo "══════════════════════════════════════════════"
        echo "  内核高危漏洞检查(CVE-2026-31431/KEV等, 共${N_RESULTS}项)"
        echo "══════════════════════════════════════════════"
        printf "  主机   : %s\n" "$HOSTNAME"
        printf "  内核   : %s  发行版: %s %s\n" "$KERNEL_FULL" "$DISTRO_ID" "$DISTRO_VER"
        printf "  内核包 : %s\n" "${PKG_VER:-n/a}"
        echo ""
        for ((i=0; i<N_RESULTS; i++)); do
            printf "  [%s] %-14s %-28s CVSS:%s\n" "${RES_STATUS[$i]}" "${RES_CVE[$i]}" "${RES_NAME[$i]}" "${RES_CVSS[$i]}"
            printf "        %s\n" "${RES_DETAIL[$i]}"
        done
        echo ""
        printf "  总体判定: %s  存在漏洞: %s\n" "$VERDICT" "${VULN_LIST:-无}"
        echo "══════════════════════════════════════════════"
        exit "$(_exit_code)"
        ;;
esac
