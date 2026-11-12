#!/bin/bash

# 定义安全版本阈值
SAFE_226="2.26.3"
SAFE_227="2.27.4"

# 通图检查 - 支持两个包同时存在，分别检测版本
egovagisserver_safe="YES"  # 整体安全状态（只要一个包不安全则为NO）
egovagisserver_info=""     # 存储两个包的版本信息

# 定义需要检查的通图JAR包名称列表（名称+标识）
target_jars=(
    "egova-service-gis-cimserver-1.1.0-SNAPSHOT.jar:cimserver"
    "egova-service-gis-gisserver-1.1.0-SNAPSHOT.jar:gisserver"
)

# 遍历所有目标JAR包，逐个检测
for jar_item in "${target_jars[@]}"; do
    # 拆分JAR包名称和标识
    jar_name=$(echo "$jar_item" | cut -d':' -f1)
    jar_type=$(echo "$jar_item" | cut -d':' -f2)
    # 查找当前JAR包路径
    jar_path=$(find /egova/web/egovagisserver/ -name "$jar_name" 2>/dev/null | head -1)
    
    if [ -n "$jar_path" ]; then
        # 提取实际版本号
        versions=$(unzip -l "$jar_path" 2>/dev/null | grep "\(BOOT-INF\|WEB-INF\)/lib/gs-main-" | awk '{print $4}' | sed 's/.*gs-main-//' | sed 's/\.jar//' | tr '\n' ',' | sed 's/,$//')
        
        # 检查版本是否安全
        is_safe="NO"
        for version in $(echo "$versions" | tr ',' ' '); do
            # 检查版本分支
            if [[ "$version" == 2.26.* ]]; then
                # 2.26.x分支，需要大于等于2.26.3
                if [ "$(printf '%s\n' "$SAFE_226" "$version" | sort -V | tail -n1)" = "$version" ]; then
                    is_safe="YES"
                fi
            elif [[ "$version" == 2.27.* ]]; then
                # 2.27.x分支，需要大于等于2.27.4
                if [ "$(printf '%s\n' "$SAFE_227" "$version" | sort -V | tail -n1)" = "$version" ]; then
                    is_safe="YES"
                fi
            fi
        done
        
        # 生成版本信息
        if [ "$is_safe" = "YES" ]; then
            jar_version_info="${jar_type}包: 安全版本 ($versions)"
        else
            jar_version_info="${jar_type}包: 实际版本: ${versions:-无}, 安全版本要求: 2.26.x >= $SAFE_226 或 2.27.x >= $SAFE_227"
            # 只要有一个包不安全，整体状态置为NO
            egovagisserver_safe="NO"
        fi
        # 拼接当前包的版本信息
        if [ -z "$egovagisserver_info" ]; then
            egovagisserver_info="$jar_version_info"
        else
            egovagisserver_info="$egovagisserver_info; $jar_version_info"
        fi
    fi
done

# 处理无任何通图包的情况
if [ -z "$egovagisserver_info" ]; then
    egovagisserver_info="未找到通图"
    egovagisserver_safe="YES"
fi

# geoserver检查 - 支持2.26.x和2.27.x版本分支
geoserver_safe="YES"
geoserver_info="未找到geoserver"

# 检查geoserver的两个可能路径
for path in "/egova/web/geoserver/WEB-INF/lib/" "/egova/web/geoserver/webapps/geoserver/WEB-INF/lib/"; do
    if [ -d "$path" ]; then
        # 提取所有gs-main版本
        versions=$(ls "${path}"gs-main-*.jar 2>/dev/null | sed 's/.*gs-main-//' | sed 's/\.jar//' | tr '\n' ',' | sed 's/,$//' 2>/dev/null || echo "无")
        
        if [ "$versions" != "无" ]; then
            # 检查版本是否安全
            is_safe="NO"
            for version in $(echo "$versions" | tr ',' ' '); do
                if [[ "$version" == 2.26.* ]]; then
                    if [ "$(printf '%s\n' "$SAFE_226" "$version" | sort -V | tail -n1)" = "$version" ]; then
                        is_safe="YES"
                    fi
                elif [[ "$version" == 2.27.* ]]; then
                    if [ "$(printf '%s\n' "$SAFE_227" "$version" | sort -V | tail -n1)" = "$version" ]; then
                        is_safe="YES"
                    fi
                fi
            done
            
            if [ "$is_safe" = "YES" ]; then
                geoserver_safe="YES"
                geoserver_info="安全版本 ($versions)"
            else
                geoserver_safe="NO"
                geoserver_info="实际版本: ${versions}, 安全版本要求: 2.26.x >= $SAFE_226 或 2.27.x >= $SAFE_227"
            fi
        else
            geoserver_safe="NO"
            geoserver_info="未找到gs-main包"
        fi
        break
    fi
done

# ==============================================================================
# 代码功能：检测 eUrbanMIS 和 eUrbanGIS 的 CellIndex 索引数据状态
# 状态定义：
#   - "已存在"：索引数据目录存在且文件数量 >= 2
#   - "未找到相关服务"：服务目录不存在
#   - "不存在"：服务目录存在，但索引数据目录不存在或文件数量 < 2
#
# 判断顺序：服务目录存在性 → 索引目录存在性 → 索引目录文件数量 >= 2
# ==============================================================================

# ------------------------------------------------------------------------------
# 检测 eUrbanMIS 文件状态
# 路径结构：/egova/web/eUrbanMIS/data
# ------------------------------------------------------------------------------
if [[ ! -d "/egova/web/eUrbanMIS" ]]; then
    # 条件1：服务根目录不存在
    cell_index_mis="未找到相关服务"
elif [[ ! -d "/egova/web/eUrbanMIS/data" ]]; then
    # 条件2：服务存在，但索引目录不存在
    cell_index_mis="不存在"
elif [[ "$(find /egova/web/eUrbanMIS/data -maxdepth 1 -type f -print -quit 2>/dev/null | wc -l)" -lt 2 ]]; then
    # 条件3：服务存在，索引目录存在，但文件数量 < 2
    cell_index_mis="不存在"
else
    # 条件4：服务存在，索引目录存在且文件数量 >= 2
    cell_index_mis="已存在"
fi

# ------------------------------------------------------------------------------
# 检测 eUrbanGIS 文件状态
# 路径结构：/egova/web/eUrbanGIS/WEB-INF/CellIndex
# ------------------------------------------------------------------------------
if [[ ! -d "/egova/web/eUrbanGIS" ]]; then
    # 条件1：服务根目录不存在
    cell_index_gis="未找到相关服务"
elif [[ ! -d "/egova/web/eUrbanGIS/WEB-INF/CellIndex" ]]; then
    # 条件2：服务存在，但索引目录不存在
    cell_index_gis="不存在"
elif [[ "$(find /egova/web/eUrbanGIS/WEB-INF/CellIndex -maxdepth 1 -type f -print -quit 2>/dev/null | wc -l)" -lt 2 ]]; then
    # 条件3：服务存在，索引目录存在，但文件数量 < 2
    cell_index_gis="不存在"
else
    # 条件4：服务存在，索引目录存在且文件数量 >= 2
    cell_index_gis="已存在"
fi

# 输出JSON
cat <<EOF
{
  "basic": {},
  "topics": {
    "01:通图版本检查": [
      {
        "01:是否安全版本::WRAPDATA_ne__quot_YES_quot_:#11547": "${egovagisserver_safe}",
        "02:版本信息": "${egovagisserver_info}"
      }
    ],
    "02:geoserver版本检查": [
      {
        "01:是否安全版本::WRAPDATA_ne__quot_YES_quot_:#7486": "${geoserver_safe}",
        "02:版本信息": "${geoserver_info}"
      }
    ],
    "03:索引检查": [
      {
        "01:eUrbanMIS 索引目录::WRAPDATA_eq__quot_不存在_quot_:#263": "${cell_index_mis}",
        "02:eUrbanGIS 索引目录::WRAPDATA_eq__quot_不存在_quot_:#263": "${cell_index_gis}"
      }
    ]
  }
}
EOF

exit 0
