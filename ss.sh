#!/bin/bash

# 函数：读取监听端口
function ss_listen_port() {
    while true; do
        read -p "请输入监听端口 (默认443): " listen_port
        listen_port=${listen_port:-443}

        if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
            echo "监听端口设置成功：$listen_port"
            break
        else
            echo "错误：监听端口范围必须在1-65535之间，请重新输入。"
        fi
    done
}

# 函数：读取加密方式
function ss_encryption_method() {
    while true; do
        read -p "请选择加密方式：
[1]. 2022-blake3-aes-128-gcm
[2]. 2022-blake3-aes-256-gcm
[3]. 2022-blake3-chacha20-poly1305
请输入对应的数字 (默认3): " encryption_choice
        encryption_choice=${encryption_choice:-3}

        case $encryption_choice in
            1)
                ss_method="2022-blake3-aes-128-gcm"
                ss_password=$(sing-box generate rand --base64 16)
                echo "随机生成的密码：$ss_password"
                break
                ;;
            2)
                ss_method="2022-blake3-aes-256-gcm"
                ss_password=$(sing-box generate rand --base64 32)
                echo "随机生成的密码：$ss_password"
                break
                ;;
            3)
                ss_method="2022-blake3-chacha20-poly1305"
                ss_password=$(sing-box generate rand --base64 32)
                echo "随机生成的密码：$ss_password"
                break
                ;;
            *)
                echo "错误：无效的选择，请重新输入。"
                ;;
        esac
    done
}

# 函数：写入sing-box配置文件
function ss_write_sing_box_config() {
    local config_file="/usr/local/etc/sing-box/config.json"

    echo "{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"shadowsocks\",
      \"tag\": \"ss-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"method\": \"$ss_method\",
      \"password\": \"$ss_password\"
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

    echo "配置文件 $config_file 创建成功。"
}

# 主函数
function main() {
    echo "配置 sing-box 配置文件"

    ss_listen_port
    ss_encryption_method

    ss_write_sing_box_config
}

main
