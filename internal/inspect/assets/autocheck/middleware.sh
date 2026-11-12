#!/bin/bash

# 循环获取绝对路径
function get_readlink() {
  local path=$1
  local flag=0
  while [ $flag -eq 0 ]; do
    temp=$(readlink $path)
    [ $? -eq 0 ] && path=${temp} || flag=$?
  done
  echo $path
}

#判断jstack是否与java路径一致(不一致代表openjdk未安装devel包)
function check_jstack() {
  jstack_path=$(which jstack 2>/dev/null)
  if [ $? -ne 0 ]; then
    jdk_devel="ERROR"
  else
    java_path=$(which java 2>/dev/null)
    java_path=$(get_readlink ${java_path})
    jstack_path=$(get_readlink ${jstack_path})
    if [[ "${java_path%/java}" == "${jstack_path%/jstack}" || "${java_path%/jre/bin/java}" == "${jstack_path%/bin/jstack}" ]]; then
      jdk_devel="OK"
    fi
  fi
}
#获取单个java进程的瞬时cpu使用率
function _get_cpu_usage() {
  top -n1 | grep java | awk '{if($2=='${pid}')print $(NF-3)}'
}

function get_statis_by_jmx_exporter() {
  local pid=$1
  local jmxPort=$2
  local apusic_flag=$3
  local open_str=${pid}
  [ ! -z "${jmxPort}" ] && open_str="127.0.0.1:${jmxPort}"

  # 请求 JMX Exporter 的 /metrics 端点，获取指标
  curl -s -u u3eya2m5i:'.-!+yb:I>rzs.uVH27hjdL]{U461gK0' http://${open_str}/metrics >/tmp/${open_str}.jmx.statis

  # 解析指标文件
  local heap_memory_max=$(grep -i "java_lang_Memory_HeapMemoryUsage_max" /tmp/${open_str}.jmx.statis | grep -v "^#" | awk '{print $2}')
  local heap_memory_used=$(grep -i "java_lang_Memory_HeapMemoryUsage_used" /tmp/${open_str}.jmx.statis | grep -v "^#" | awk '{print $2}')
  local non_heap_memory_used=$(grep -i "java_lang_Memory_NonHeapMemoryUsage_used" /tmp/${open_str}.jmx.statis | grep -v "^#" | awk '{print $2}')
  local thread_count=$(grep -i "java_lang_Threading_ThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" | awk '{print $2}')
  local peak_thread_count=$(grep -i "java_lang_Threading_PeakThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" | awk '{print $2}')
  local nio_direct_memory_used=$(grep -i "java_nio_BufferPool_MemoryUsed{name=\"direct\"}" /tmp/${open_str}.jmx.statis | grep -v "^#" | awk '{print $2}')
  local http_threads_busy=""
  local http_threads_count=""
  local http_threads_max=""
  if [ "${apusic_flag}" == "true" ]; then
        http_threads_busy=$(grep -i "apusic_ThreadPool_BusyThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" | grep "HTTPHandler" | awk '{print $2}')
        http_threads_count=$(grep -i "apusic_ThreadPool_CurrentThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" | grep "HTTPHandler" | awk '{print $2}')
        http_threads_max=$(grep -i "apusic_ThreadPool_MaxThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" | grep "HTTPHandler" | awk '{print $2}')
  elif [ "${tongweb_flag}" == "true" ]; then
        http_threads_busy=$(grep -i "TONGWEB_ThreadPool_currentThreadsBusy" /tmp/${open_str}.jmx.statis | grep -v "^#" |grep "${serverPort}" | awk '{print $2}')
        http_threads_count=$(grep -i "TONGWEB_ThreadPool_currentThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" |grep "${serverPort}" | awk '{print $2}')
        http_threads_max=$(grep -i "TONGWEB_ThreadPool_maxThreads" /tmp/${open_str}.jmx.statis | grep -v "^#" | grep "${serverPort}" | awk '{print $2}')
  elif [ "${bes_flag}" == "true" ]; then
        http_threads_busy=$(grep -i "com_bes_appserv_ThreadPool_currentThreadsBusy" /tmp/${open_str}.jmx.statis | grep -v "^#" |grep "${serverPort}" | awk '{print $2}')
        http_threads_count=$(grep -i "com_bes_appserv_ThreadPool_currentThreadCount" /tmp/${open_str}.jmx.statis | grep -v "^#" |grep "${serverPort}" | awk '{print $2}')
        http_threads_max=$(grep -i "com_bes_appserv_ThreadPool_maxThreads" /tmp/${open_str}.jmx.statis | grep -v "^#" | grep "${serverPort}" | awk '{print $2}')
  fi

  echo "$(
    cat <<EOF
            {
              "01:port:NO_FORMAT": ${serverPort:-0},
              "02:pid:NO_FORMAT": ${pid:-0},
              "03:cpu_used%::DATA_gt_200:#9788":${cpu_used},
              "04:Heap_Memory_Max:B:": ${heap_memory_max:--1},
              "05:Heap_Memory_Used:B:DATA_gt_3221225472:#9788": ${heap_memory_used:--1},
              "06:Non_Heap_Memory_Used:B:DATA_gt_1073741824:#9788":${non_heap_memory_used:--1},
              "07:http_threads_used::DATA_gt_200:#9788":${http_threads_count:--1},
              "08:http_threads_busy::DATA_gt_10:#9788":${http_threads_busy:--1},
              "09:http_threads_max::DATA_lt_500:#9788":${http_threads_max:--1},
              "10:jvm_threads_count::DATA_gt_1000:#9788":${thread_count:--1},
              "11:jvm_peak_threads_count::DATA_gt_10000:#9788":${peak_thread_count:--1},
              "12:nio_direct_memory_used:B:DATA_gt_536870912:#9788": ${nio_direct_memory_used:--1}
            }
EOF
  )"

}

function get_middleware_configuration() {
  local pid=$1
  local apusic_flag=$2
  local log_size=$(du ${rootDir}/logs --max-depth=0 | awk '{print $1}')
  local info_log_count=""
  if [ "${apusic_flag}" == "true" ]; then
    info_log_count=$(ls ${web_logs_dir}/apusic* 2>/dev/null | wc -l)
  else
    # 东方通和宝蓝德逻辑一致，不再特别处理
    info_log_count=$(ls ${web_logs_dir}/server* 2>/dev/null | wc -l)
  fi
  local yesterday=$(date -d "-1 days" +%Y-%m-%d)
   # 检查是否存在前一天的 server_YYYY-MM-DD_1.log 文件
   if [ ${info_log_count} -gt 0 ] && [ "${apusic_flag}" == "false" ] && [ -e "${web_logs_dir}/server_${yesterday}_1.log" ]; then
        logrotate_status="YES"
   elif [ ${info_log_count} -gt 0 ] && [ "${apusic_flag}" == "true" ] && [ -e "${web_logs_dir}/apusic_${yesterday}_1.log" ]; then
        logrotate_status="YES"
   else

        logrotate_status="NO"
   fi
  echo "$(
    cat <<EOF
            {
              "01:home": "${rootDir:-None}",
              "02:pid:NO_FORMAT": ${pid:-0},
              "04:jmxagent": "${jmxAgent:-NO}",
              "05:Xmx:MB:DATA_gt_6144:#9817": "${Xmx:-0}",
              "06:HeapDumpPath::WRAPDATA_eq__quot_NO_quot_:#9817": "${HeapDumpPath:-NO}",
              "07:total_log_size:KB:DATA_gt_10485760:#9783":${log_size},
              "08:info_file_count::DATA_gt_14_or_DATA_lt_1:#9783": ${info_log_count:--1},
              "09:log_level::WRAPDATA_eq__quot_NO_quot_:#9817":"${logLevel:-NO}",
              "10:logrotate::WRAPDATA_eq__quot_NO_quot_:#9817":"${logrotate_status:-NO}"
            }
EOF
  )"
}

function stat_multi_error_log() {
  local app_names=("eUrbanSG" "eGovaPublic" "faceserver" "statgather" "eUrbanUMA" "eUrbanMF" "eUrbanMIS")
  tempfile=""
  big_logs=""
  for app_name in ${app_names[@]}; do
    web_logs_dir="/egova/web/${app_name}/WEB-INF/log"

    # 检查 web_logs_dir 是否存在
    if [ ! -d "${web_logs_dir}" ]; then
      continue
    fi

    if [ $(date +%H) -lt "12" ]; then
      file=${web_logs_dir}/eurban_info.log.$(date -d "-1 days" +%Y-%m-%d)
    else
      file=${web_logs_dir}/eurban_info.log
    fi

    # 检查日志文件是否存在
    if [ -e "${file}" ]; then
      _log_size=$(du ${file} | awk '{print $1}')
      if [ ${_log_size} -gt 3145728 ]; then
        big_logs="${big_logs}{\"01:log\":\"$file\",\"02:log_size::DATA_gt_3145728:#9817\":${_log_size}},"
        continue
      fi

      # 检查临时文件状态
      if [ -z "${tempfile}" ]; then
        tempfile=${file}.error
        rm -rf ${tempfile}
      fi

      cat ${file} | grep -i "ERROR" -A 100 | sed 's/\\/\\\\/g' >>${tempfile}
    fi
  done

  if [ -e ${tempfile} ]; then
    rm -rf /tmp/.ac_tomcat_error.json
    if [ -n "${AUTOCHECK_NODE_BIN}" ] && [ -x "${AUTOCHECK_NODE_BIN}" ]; then
      "${AUTOCHECK_NODE_BIN}" node --check log4j-stat --set log="${tempfile}" --set legacy=1 1>/tmp/.ac_tomcat_error.json 2>/tmp/.ac_tomcat_err.log
    else
      /usr/bin/log4j-stat.py ${tempfile} 1>/tmp/.ac_tomcat_error.json 2>/tmp/.ac_tomcat_err.log
    fi
  fi

  if [ ! -z "$big_logs" ]; then
    big_logs="[${big_logs%?}]"
  fi

  error_order_by_exception="$(cat /tmp/.ac_tomcat_error.json | jq -cr .error_order_by_exception)"
  error_order_by_at_class="$(cat /tmp/.ac_tomcat_error.json | jq -cr .error_order_by_at_class)"
}

function get_busy_thread_info() {
  local pid=$1
  local info=$(timeout 5 busythread -p ${pid} | sed "s/\"//g" | sed "s/#//g" | sed ':a;N;$!ba;s/\n/<br\/>/g')
  echo "$(
    cat <<EOF
            {
              "01:pid:NO_FORMAT": "${pid}",
              "02:busythread":"${info}"
            },
EOF
  )"
}

function get_all_middleware_info() {
  apusic_flag=false
  tongweb_flag=false
  bes_flag=false

  pids=$(jps -l | grep tongweb | awk '{print $1}')
  if [[ -z "$pids" ]]; then
    pids=$(jps -l | grep apusic | awk '{print $1}')
    if [[ -z "$pids" ]]; then
      pids=$(jps -l | grep bes | awk '{print $1}')
      [[ -z "$pids" ]] || bes_flag=true
    else
      apusic_flag=true
    fi 
  else
    tongweb_flag=true
  fi

  topic_configs=""
  topic_jvm_infos=""
  topic_errors=""
  topic_busy_thread=""
  homes=""
  for pid in ${pids}; do
    rootDir=""
    jmxArgs=""
    jmxAgent=""
    jmxPort=""
    Xmx=""
    HeapDumpPath=""
    logLevel=""
    serverPort=""
    if [ "${apusic_flag}" == "true" ]; then
           eval "$(ps -ef | grep -v grep | awk '{if($2=='${pid}'){for(i=1;i<=NF;i++){if($i~/-Dcom.apusic.domain.home=/){split($i,c,"=");print "rootDir="c[2]} if($i~/XX:HeapDumpPath/){split($i,c,"=");print "HeapDumpPath="c[2]}  if($i~/Xmx/){split($i,c,"mx");print "Xmx="c[2]} if($i~/jmx_prometheus_javaagent/){print "jmxArgs="$i}  }}}')"
    elif [ "${tongweb_flag}" == "true" ]; then
          eval "$(ps -ef | grep -v grep | awk '{if($2=='${pid}'){for(i=1;i<=NF;i++){if($i~/-Dtongweb.home=/){split($i,c,"=");print "rootDir="c[2]} if($i~/XX:HeapDumpPath/){split($i,c,"=");print "HeapDumpPath="c[2]}  if($i~/Xmx/){split($i,c,"mx");print "Xmx="c[2]} if($i~/jmx_prometheus_javaagent/){print "jmxArgs="$i}  }}}')"
    elif [ "${bes_flag}" == "true" ]; then
          eval "$(ps -ef | grep -v grep | awk '{if($2=='${pid}'){for(i=1;i<=NF;i++){if($i~/-Dbes.home=/){split($i,c,"=");print "rootDir="c[2]} if($i~/XX:HeapDumpPath/){split($i,c,"=");print "HeapDumpPath="c[2]}  if($i~/Xmx/){split($i,c,"mx");print "Xmx="c[2]} if($i~/jmx_prometheus_javaagent/){print "jmxArgs="$i}  }}}')"
    fi

    # 清理 Xmx 单位后缀，实现 GB/MB 智能换算为 MB
    Xmx=$([[ ${Xmx} =~ [gG] ]] && echo $((${Xmx%%[a-zA-Z]*}*1024)) || echo ${Xmx%%[a-zA-Z]*})

    if [[ -n "$jmxArgs" ]]; then
      jmxAgent=YES
      jmxPort=$(echo "$jmxArgs" | awk -F'=' '{print $2}' | awk -F':' '{print $1}')
    fi

    homes="${homes}${rootDir}"
    if [ "${apusic_flag}" == "true" ]; then
      serverPort=$(grep -oP '(?<=<ATTRIBUTE NAME="Port" VALUE=")[^"]+' "${homes}/config/apusic.conf")
    elif [ "${tongweb_flag}" == "true" ]; then
      serverPort=$(grep -oP '(?<=<http-listener name="tong-http-listener" port=")[^"]+' "${homes}/conf/tongweb.xml")
    elif [ "${bes_flag}" == "true" ]; then
      serverPort=$(grep -P '<http-listener\s' "${homes}/conf/server.config" | grep -P '\senabled="true"' | grep -P '\sdefault-virtual-server="server"' | grep -oP '(?<=port=")\d+')
    fi

    # 递归查找 web_logs 文件夹
    web_logs_dir="${rootDir}/logs"
    cpu_used=$(_get_cpu_usage $pid)
    [ -z "${cpu_used}" ] && cpu_used="0"
    topic_configs="${topic_configs}$(get_middleware_configuration ${pid} ${apusic_flag}),"
    topic_jvm_infos="${topic_jvm_infos}$(get_statis_by_jmx_exporter ${pid} ${jmxPort} ${apusic_flag}),"
    if [ ${cpu_used%.*} -gt 150 ]; then
      topic_busy_thread="${topic_busy_thread}$(get_busy_thread_info ${pid})"
    fi
  done
  # stat_multi_error_log "$homes"
}

function get_basic_info() {
  java_version=$(java -version 2>&1 | grep version | awk '{print $3}' | sed "s/\"//g")
  java_count=$(jps 2>/dev/null | grep -v Jps 2>/dev/null | wc -l)
  check_jstack
  all_cpu_used=$(top -n1 | grep "Cpu(s):" | awk '{split($2,a,"%");print a[1]}')
  basic=$(
    cat <<EOF
            {
              "01:version": "${java_version:-None}",
              "02:process_count":"${java_count}",
              "03:jdk_devel::WRAPDATA_eq__quot_ERROR_quot_:#9817": "${jdk_devel:-ERROR}",
              "04:cpu_used%::DATA_gt_50:#9788": ${all_cpu_used:-0}
            }
EOF
  )
}
function main() {
  get_basic_info
  get_all_middleware_info
  check_facts=$(
    cat <<EOF
  {
    "basic":${basic},
    "topics":{
        "01:middleware_config":[${topic_configs%?}],
        "02:jvm_statistics":[${topic_jvm_infos%?}],
        "03:busythread":[${topic_busy_thread%?}]
    }
  }
EOF
  )
  echo "${check_facts:-[]}"
}

main
