#!/bin/bash

function get_system() {
  # 获取系统信息

  hostname=$(hostname 2>/dev/null)
  distribution=$(awk '/^ID=/' /etc/*-release 2>/dev/null | awk -F'=' '{gsub("\"","");print $2}')
  [ -z $distribution ] &&  distribution=$(cat /etc/*-release 2>/dev/null|head -1|awk '{print $1}')
  distribution_version=$(awk -F= '/^VERSION_ID=/{gsub("\"","");print $2}' /etc/os-release 2>/dev/null)
  [ -z $distribution_version ] && distribution_version=$(awk '/^VERSION_ID=/' /etc/*-release 2>/dev/null | awk -F'=' '{gsub("\"","");print $2}')
  kernel=$(uname -r 2>/dev/null)
  os_time=$(date +"%F %T" 2>/dev/null)
  uptime=$(uptime 2>/dev/null |awk '{print $3}'|awk -F, '{print $1}')
  if [ ! -z $timestamp_host ];then
    set +e
    timeout 2 clockdiff $timestamp_host 2>/dev/null 1>/tmp/clockdiff.txt
    [ $? -gt 0 ] && timeout 2 clockdiff -o $timestamp_host 2>/dev/null 1>/tmp/clockdiff.txt
    [ $? -gt 0 ] && timeout 2 clockdiff -o1 $timestamp_host 2>/dev/null 1>/tmp/clockdiff.txt
    [ $? -eq 0 ] && clock_diff=$(awk '{print $2/1000}' /tmp/clockdiff.txt)

    #尝试使用http获取时间差
    if [ -z "$clock_diff" ] && [ ! -z "${timestamp_port}" ] ;then
        code=$(timeout 6 curl --connect-timeout 3 http://$timestamp_host:${timestamp_port}/ts -w %{http_code} -o /tmp/server.timestamp -s)
        if [ "$code" == "200" ];then
            current_ts=$(date -d "$(stat /tmp/server.timestamp |grep -E "^Modify|最近改动"|awk -F"[. ：]" '{print $2,$3}')" +%s)
            server_ts=$(date -d "$(cat /tmp/server.timestamp | sed "s/T/ /g" |sed "s/+08:00//g" )" +%s)
            clock_diff=`expr ${current_ts} - ${server_ts}`
        fi

    fi
    set -e
  fi
  set +e
  mount -a 2>/dev/null 1>/dev/null
  [ $? -eq 0 ] && fstab_ok="OK"
  set +e
  system_facts=$(cat << EOF
  {
    "01:hostname": "${hostname:-}",
    "02:distribution": "${distribution}${distribution_version}",
    "03:kernel": "${kernel:-}",
    "04:os_time": "${os_time:-}",
    "05:clock_diff:s:abs_lbc_DATA_rbc_gt_10:#9775": "${clock_diff:-99999}",
    "06:uptime_days": "${uptime:-}",
    "07:fstab::WRAPDATA_eq__quot_ERROR_quot_:#9776": "${fstab_ok:-ERROR}"
  }
EOF
  )

}


function get_cpu() {
  # 获取cpu使用信息

  #不兼容centos6
  #cpu_usedutilization=$(cat <(grep 'cpu ' /proc/stat) <(sleep 1 && grep 'cpu ' /proc/stat) | awk -v RS="" '{printf ("%.2f\n", ($13-$2+$15-$4)*100/($13-$2+$15-$4+$16-$5))}')
  cpu_usedutilization=$(cat <(grep 'cpu ' /proc/stat) <(sleep 1 && grep 'cpu ' /proc/stat)| awk '{print $2,$4,$5}'| awk -v RS="" '{printf ("%.2f\n", ($4-$1+$5-$2)*100/($4-$1+$5-$2+$6-$3))}')
  cpu_loadavg1=$(awk '{print $1}' /proc/loadavg)
  cpu_loadavg5=$(awk '{print $2}' /proc/loadavg)
  cpu_loadavg15=$(awk '{print $3}' /proc/loadavg)
  cpu_processors=$(cat /proc/cpuinfo | grep "processor" | wc -l)
  cpu_facts=$(cat << EOF
  [{
    "01:cpu_used%:%:DATA_gt_60:#4864": ${cpu_usedutilization:-0},
    "02:cpu_loadavg1::DATA_gt_10:#4864": ${cpu_loadavg1:-0},
    "03:cpu_loadavg5::DATA_gt_10:#4864": ${cpu_loadavg5:-0},
    "04:cpu_loadavg15::DATA_gt_10:#4864": ${cpu_loadavg15:-0},
    "05:cpu_processors": ${cpu_processors:-0}
  }]
EOF
  )

}


function get_mem() {
  # 获取内存使用信息
  
  memfree=$(awk -F":|kB" '$1~/^MemFree/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)
  memavailable=$(awk -F":|kB" '$1~/^MemAvailable/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)
  memtotal=$(awk -F":|kB" '$1~/^MemTotal/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)
  memcache=$(awk -F":|kB" '$1~/^Cached/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)
  membuffer=$(awk -F":|kB" '$1~/^Buffers/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)
  swaptotal=$(awk -F":|kB" '$1~/^SwapTotal/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)
  swapfree=$(awk -F":|kB" '$1~/^SwapFree/{gsub(/ +/,"",$0);print $2}' /proc/meminfo)

  [ -z ${memavailable} ] && memavailable=$(echo "${memfree:-0} ${memcache:-0} ${membuffer:-0}"| awk '{printf $1+$2+$3}')
  [ "${memtotal:-0}" != "0" ] && mem_usedutilization=$(echo "${memtotal:-0} ${memfree:-0} ${memcache:-0} ${membuffer:-0}" | awk '{printf ("%.2f\n", ($1-$2-$3-$4)*100/$1)}') 
  [ "${swaptotal:-0}" != "0" ] && swap_usedutilization=$(echo "${swaptotal:-0} ${swapfree:-0}"| awk '{printf ("%.2f\n", ($1-$2)*100/$1)}')
  
  mem_facts=$(cat << EOF
  [{
    "01:memory_total:KB": ${memtotal:-},
    "02:memory_free:KB": ${memfree:-},
    "03:memory_available:KB": ${memavailable:-},
    "04:memory_cache:KB": ${memcache:-},
    "05:memory_buffer:KB": ${membuffer:-},
    "06:memory_used%:%:DATA_gt_90:#4891": ${mem_usedutilization:-0},
    "07:swap_total:KB": ${swaptotal:-},
    "08:swap_free:KB": ${swapfree:-},
    "09:swap_used%:%:DATA_gt_90:#4891": ${swap_usedutilization:-0}
  }]
EOF
  )
  

}


function get_disk() {
  # 获取磁盘使用信息  

  mount=$(grep '^/dev/' /proc/mounts | grep -v -E 'docker|containers|iso9660|kubelet|boot' | awk '{print $2}')
  
  for m in ${mount:-}; do
    size_total=$(df -P $m 2>/dev/null | awk 'END{print $2}')
    size_use=$(df -P $m 2>/dev/null | awk 'END{print $3}')
    size_available=$(df -P $m 2>/dev/null | awk 'END{print $4}')
    size_usedutilization=$(df -P $m 2>/dev/null | awk 'END{sub(/'%'/,"");print $5}')
    size_check=$([[ $size_available -ge 10240000 && $size_usedutilization -ge 80 ]] && echo "磁盘空间告罄" || echo "磁盘空间充裕")
    inode_total=$(df -Pi $m 2>/dev/null | awk 'END{print $2}')
    inode_use=$(df -Pi $m 2>/dev/null | awk 'END{print $3}')
    inode_available=$(df -Pi $m 2>/dev/null | awk 'END{print $4}')
    inode_usedutilization=$(df -Pi $m 2>/dev/null | awk 'END{sub(/'%'/,"");print $5}')
    in_fstab=$(cat /etc/fstab|grep -v -E "^#|^$"|awk 'BEGIN{cnt=0}{if($2=="'$m'")cnt+=1}END{if(cnt<1){print "NO"}else{print "YES"}}')
    mount_facts=${mount_facts:-''}$(cat <<EOF
    {
      "01:mount": "${m:-}",
      "02:in_fstab::WRAPDATA_eq__quot_NO_quot_:#9776": "${in_fstab:-NO}",
      "03:size_total:KB": ${size_total:-},
      "04:size_use:KB": ${size_use:-},
      "05:size_available:KB": ${size_available:-},
      "06:size_used%:%": ${size_usedutilization:-0},
      "07:size_check:::#4870": "${size_check:-}",
      "08:inode_total": ${inode_total:-},
      "09:inode_used": ${inode_use:-},
      "10:inode_available::DATA_lt_100000:#4908": ${inode_available:-},
      "11:inode_used%:%:DATA_gt_90:#4908": ${inode_usedutilization:-0}
    },
EOF
    )

  done

  disk_facts="["${mount_facts%?}"]"

}


function get_network() {
  # 获取网络信息

  stat=$(netstat -ant|awk  '$1~/tcp/{++S[$NF]}END{for(m in S) print "\"01:" m "::DATA_gt_5000:#9779\":",S[m] ","}')
  
  conn="False"
  curl -V >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    timeout 6 curl --connect-timeout 3 --max-time 1 -sI http://www.baidu.com 2>/dev/null | grep '200 OK' >/dev/null 2>&1
    [ $? -eq 0 ] && conn="True"
  fi
  network_facts=$(cat << EOF
  [{
    "01:tcpconnection:::#9779": {${stat%?}},
    "00:access_to_internet": "${conn}"
  }]
EOF
  )

}


function main() {
  # 脚本主要流程
  
  get_system
  get_cpu
  get_mem
  get_disk
  get_network
  

  check_facts=$(cat << EOF
  {
    "basic": ${system_facts:-[]},
    "topics":{
        "01:cpu": ${cpu_facts:-[]},
        "02:memory": ${mem_facts:-[]},
        "03:disk": ${disk_facts:-[]},
        "04:network": ${network_facts:-[]}
    }
  }
EOF
  )
  
  echo "${check_facts:-[]}"

}


while [ -n "$1" ]; do
    case "$1" in
    --timestamp-host=*)
        timestamp_host="$(echo $1|awk -F= '{print $2}')"
        shift 1
        ;;
    --timestamp-port=*)
        timestamp_port="$(echo $1|awk -F= '{print $2}')"
        shift 1
        ;;
    *)
        shift 1
        break
        ;;
    esac
done

main
