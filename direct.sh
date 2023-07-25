#!/bin/bash

# 函数：读取监听端口
function Direct_listen_port() {
    while true; do
        read -p "请输入监听端口 (默认443): " listen_port
        listen_port=${listen_port:-443}

        if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
            break
        else
            echo "错误：监听端口范围必须在1-65535之间，请重新输入。"
        fi
    done
}

# 函数：读取目标地址
function Direct_override_address() {
    local is_valid_address=false

    while [[ "$is_valid_address" == "false" ]]; do
        read -p "请输入目标地址: " override_address

        # 使用正则表达式检查是否为合法的 IPv4 地址
        if [[ $override_address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # 检查每个字段是否在 0 到 255 之间
            IFS='.' read -r -a address_fields <<< "$override_address"
            is_valid_ip=true
            for field in "${address_fields[@]}"; do
                if [[ "$field" -lt 0 || "$field" -gt 255 ]]; then
                    is_valid_ip=false
                    break
                fi
            done

            if [[ "$is_valid_ip" == "true" ]]; then
                is_valid_address=true
            else
                echo "错误：IP地址字段必须在0到255之间，请重新输入。"
            fi
        else
            echo "错误：请输入合法的IPv4地址，格式为 0.0.0.0。"
        fi
    done
}

# 函数：读取目标端口
function Direct_override_port() {
    while true; do
        read -p "请输入目标端口 (默认443): " override_port
        override_port=${override_port:-443}

        if [[ $override_port =~ ^[1-9][0-9]{0,4}$ && $override_port -le 65535 ]]; then
            break
        else
            echo "错误：目标端口范围必须在1-65535之间，请重新输入。"
        fi
    done
}

# 函数：写入配置文件
function Direct_write_config_file() {
    local config_file="/usr/local/etc/sing-box/config.json"

    echo "{
  \"log\": {
    \"disabled\": false,
    \"level\": "info",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct-in\",
      \"listen\": \"0.0.0.0\",
      \"listen_port\": $listen_port,
      \"sniff\": true,
      \"sniff_override_destination\": true,
      \"sniff_timeout\": \"300ms\",
      \"proxy_protocol\": false,
      \"network\": \"tcp\",
      \"override_address\": \"$override_address\",
      \"override_port\": $override_port
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" > "$config_file"

    echo "配置文件 $config_file 写入成功。"
}

# 主函数
function main() {
    echo "========================="
    echo "  配置 sing-box 配置文件"
    echo "========================="

    Direct_listen_port
    Direct_override_address
    Direct_override_port
    Direct_write_config_file
}

main
