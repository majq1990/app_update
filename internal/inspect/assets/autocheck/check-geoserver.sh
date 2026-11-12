#!/bin/bash

# GeoServer 的默认凭据
DEFAULT_USERNAME="admin"
DEFAULT_PASSWORD="geoserver"
REQUIRED_VERSION="2.25.4"

# 要检查的服务器地址和端口
SERVER="127.0.0.1"

PORTS=("8081" "8080")

# 检查默认密码的函数
check_default_password() {
    local port=$1
    local protocols=("http" "https")
    local success="NO"

    for protocol in "${protocols[@]}"; do
        # 尝试带端口的 URL
        local url="${protocol}://${SERVER}:${port}/geoserver/rest"
        local url1="${protocol}://${SERVER}:${port}/web"

        # 尝试不带端口的 URL
        local url_no_port="${protocol}://${SERVER}/geoserver/rest"
        local url1_no_port="${protocol}://${SERVER}/web"

        # 尝试带端口的第一种 URL
        response=$(curl -s -o /dev/null -w "%{http_code}" -u "$DEFAULT_USERNAME:$DEFAULT_PASSWORD" --insecure "$url")
        if [ "$response" == "200" ]; then
            success="YES"
            break
        fi

        # 尝试带端口的第二种 URL
        response=$(curl -s -o /dev/null -w "%{http_code}" -u "$DEFAULT_USERNAME:$DEFAULT_PASSWORD" --insecure "$url1")
        if [ "$response" == "200" ]; then
            success="YES"
            break
        fi

        # 尝试不带端口的第一种 URL
        response=$(curl -s -o /dev/null -w "%{http_code}" -u "$DEFAULT_USERNAME:$DEFAULT_PASSWORD" --insecure "$url_no_port")
        if [ "$response" == "200" ]; then
            success="YES"
            break
        fi

        # 尝试不带端口的第二种 URL
        response=$(curl -s -o /dev/null -w "%{http_code}" -u "$DEFAULT_USERNAME:$DEFAULT_PASSWORD" --insecure "$url1_no_port")
        if [ "$response" == "200" ]; then
            success="YES"
            break
        fi
    done

    echo "$success"
}

# 获取版本信息的函数
get_geoserver_version() {
    local port=$1
    local protocols=("http" "https")
    local version="无法从页面中获取 GeoServer 版本信息。"

    for protocol in "${protocols[@]}"; do
        # 尝试带端口的 URL
        local url1="${protocol}://${SERVER}:${port}/geoserver/web/?wicket:bookmarkablePage=:org.geoserver.web.AboutGeoServerPage"
        local url2="${protocol}://${SERVER}:${port}/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage"
        local url3="${protocol}://${SERVER}:${port}/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage"

        # 尝试不带端口的 URL
        local url1_no_port="${protocol}://${SERVER}/geoserver/web/?wicket:bookmarkablePage=:org.geoserver.web.AboutGeoServerPage"
        local url2_no_port="${protocol}://${SERVER}/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage"
        local url3_no_port="${protocol}://${SERVER}/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage"

        # 尝试带端口的第一种 URL
        response=$(curl -s --insecure "$url1")
        if echo "$response" | grep -q '<span id="version">'; then
            version=$(echo "$response" | grep '<span id="version">' | sed -e 's/.*<span id="version">\([^<]*\).*/\1/')
            break
        fi

        # 尝试带端口的第二种 URL
        response=$(curl -s --insecure "$url2")
        if echo "$response" | grep -q '<span id="version">'; then
            version=$(echo "$response" | grep '<span id="version">' | sed -e 's/.*<span id="version">\([^<]*\).*/\1/')
            break
        fi

        # 尝试带端口的第三种 URL
        response=$(curl -s --insecure "$url3")
        if echo "$response" | grep -q '<span id="version">'; then
            version=$(echo "$response" | grep '<span id="version">' | sed -e 's/.*<span id="version">\([^<]*\).*/\1/')
            break
        fi

        # 尝试不带端口的第一种 URL
        response=$(curl -s --insecure "$url1_no_port")
        if echo "$response" | grep -q '<span id="version">'; then
            version=$(echo "$response" | grep '<span id="version">' | sed -e 's/.*<span id="version">\([^<]*\).*/\1/')
            break
        fi

        # 尝试不带端口的第二种 URL
        response=$(curl -s --insecure "$url2_no_port")
        if echo "$response" | grep -q '<span id="version">'; then
            version=$(echo "$response" | grep '<span id="version">' | sed -e 's/.*<span id="version">\([^<]*\).*/\1/')
            break
        fi

        # 尝试不带端口的第三种 URL
        response=$(curl -s --insecure "$url3_no_port")
        if echo "$response" | grep -q '<span id="version">'; then
            version=$(echo "$response" | grep '<span id="version">' | sed -e 's/.*<span id="version">\([^<]*\).*/\1/')
            break
        fi
    done

    echo "$version"
}

# 比较版本号的函数
compare_versions() {
    [[ "$1" == "$(printf "$1\n$2" | sort -V | tail -n1)" ]]
}

# 主程序
#echo "正在检查 GeoServer 的默认密码和版本信息..."

# 初始化结果变量
default_password_check="未部署"
version_check="未部署"
version_info="未部署"

for port in "${PORTS[@]}"; do
    # echo "检查端口 $port..."
    password_result=$(check_default_password "$port")
    version=$(get_geoserver_version "$port")

    if [[ $password_result == "YES" ]]; then
        default_password_check="YES"
    else
        default_password_check="NO"
    fi

    if [[ $version != "无法从页面中获取 GeoServer 版本信息。" ]]; then
        version_info=$version
        if compare_versions "$version" "$REQUIRED_VERSION"; then
            version_check="YES"
        else
            version_check="NO"
        fi
    else
        default_password_check="未部署"
        version_check="未部署"
        version_info="未部署"
    fi
done

# 输出最终的 JSON 结果
cat <<EOF
{
  "basic": {},
  "topics": {
    "01:geoserver版本与默认密码检查": [
      {
        "01:是否使用默认密码::WRAPDATA_eq__quot_YES_quot_": "$default_password_check",
        "02:版本检查::WRAPDATA_eq__quot_NO_quot_": "$version_check",
        "03:版本信息": "$version_info"
      }
    ]
  }
}
EOF
