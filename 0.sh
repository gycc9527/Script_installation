# 函数：根据系统版本自动安装依赖
install_dependencies() {
    local os_version
    os_version=$(lsb_release -si 2>/dev/null)

    local dependencies
    local common_dependencies="wget tar socat jq git openssl"

    case "$os_version" in
        Debian|Ubuntu)
            dependencies="$common_dependencies uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev"
            ;;
        CentOS)
            dependencies="$common_dependencies util-linux gcc-c++ zlib-devel openssl-devel libevent-devel"
            ;;
        *)
            echo "不支持的操作系统: $os_version"
            exit 1
            ;;
    esac

    if ! command -v apt-get &> /dev/null && ! command -v dnf &> /dev/null && ! command -v yum &> /dev/null; then
        echo "不支持的包管理器，无法继续安装依赖。"
        exit 1
    fi

    echo "更新软件包列表..."
    if command -v apt-get &> /dev/null; then
        apt-get update
    elif command -v dnf &> /dev/null; then
        dnf makecache
    elif command -v yum &> /dev/null; then
        yum makecache
    fi

    echo "下载并安装依赖..."
    if command -v apt-get &> /dev/null; then
        apt-get install -y $dependencies
    elif command -v dnf &> /dev/null; then
        dnf install -y $dependencies
    elif command -v yum &> /dev/null; then
        yum install -y $dependencies
    fi

    echo "依赖已安装。"
}



# 检查防火墙配置
function check_firewall_configuration() {
    local os_name=$(uname -s)
    local firewall

    if [[ $os_name == "Linux" ]]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            firewall="ufw"
        elif command -v iptables >/dev/null 2>&1 && iptables -S | grep -q "INPUT -j DROP"; then
            firewall="iptables"
        elif command -v firewalld >/dev/null 2>&1 && firewall-cmd --state | grep -q "running"; then
            firewall="firewalld"
        fi
    fi

    if [[ -z $firewall ]]; then
        echo "未检测到防火墙配置或防火墙未启用，跳过配置防火墙。"
        return
    fi

    echo "检查防火墙配置..."

    case $firewall in
        ufw)
            if ! ufw status | grep -q "Status: active"; then
                ufw enable
            fi

            if ! ufw status | grep -q " $listen_port"; then
                ufw allow "$listen_port"
            fi

            if ! ufw status | grep -q " $override_port"; then
                ufw allow "$override_port"
            fi

            if ! ufw status | grep -q " 80"; then
                ufw allow 80
            fi

            echo "防火墙配置已更新。"
            ;;
       iptables)
            if ! iptables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT
            fi

            if ! iptables -C INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport "$listen_port" -j ACCEPT
            fi

            if ! iptables -C INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport "$override_port" -j ACCEPT
            fi

            if ! iptables -C INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport "$override_port" -j ACCEPT
            fi

            if ! iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport 80 -j ACCEPT
            fi

            if ! iptables -C INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport 80 -j ACCEPT
            fi

            iptables-save > /etc/sysconfig/iptables

            echo "iptables防火墙配置已更新。"
            ;;
        firewalld)
            if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp"; then
                firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp"; then
                firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/tcp"; then
                firewall-cmd --zone=public --add-port="$override_port/tcp" --permanent
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/udp"; then
                firewall-cmd --zone=public --add-port="$override_port/udp" --permanent
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "80/tcp"; then
                firewall-cmd --zone=public --add-port=80/tcp --permanent
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "80/udp"; then
                firewall-cmd --zone=public --add-port=80/udp --permanent
            fi

            firewall-cmd --reload

            echo "firewalld防火墙配置已更新。"
            ;;
    esac
}

# 检查 sing-box 文件夹是否存在，如果不存在则创建
function check_sing_box_folder() {
    local folder="/usr/local/etc/sing-box"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}

# 检查 caddy 文件夹是否存在，如果不存在则创建
function check_caddy_folder() {
    local folder="/usr/local/etc/caddy"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}


# 创建文件目录
function create_tuic_directory() {
    local tuic_directory="/usr/local/etc/tuic"
    local ssl_directory="/etc/ssl/private"
    
    if [[ ! -d "$tuic_directory" ]]; then
        mkdir -p "$tuic_directory"
    fi
    
    if [[ ! -d "$ssl_directory" ]]; then
        mkdir -p "$ssl_directory"
    fi
}

# 函数：开启 BBR
enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "开启 BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo "BBR 已开启"
    else
        echo "BBR 已经开启，跳过配置。"
    fi
}

# 选择安装方式
function select_sing_box_install_option() {
    while true; do
        echo "请选择 sing-box 的安装方式："
        echo "  [1]. 编译安装sing-box（支持全部功能）"
        echo "  [2]. 下载安装sing-box（支持部分功能）"

        local install_option
        read -p "请选择 [1-2]: " install_option

        case $install_option in
            1)
                install_go
                compile_install_sing_box
                break
                ;;
            2)
                install_latest_sing_box
                break
                ;;
            *)
                echo "无效的选择，请重新输入。"
                ;;
        esac
    done
}

# 函数：检查并安装 Go
install_go() {
    if ! command -v go &> /dev/null; then
        echo "下载并安装 Go..."
        local go_arch
        case $(uname -m) in
            x86_64)
                go_arch="amd64"
                ;;
            i686)
                go_arch="386"
                ;;
            aarch64)
                go_arch="arm64"
                ;;
            armv6l)
                go_arch="armv6l"
                ;;
            *)
                echo "不支持的架构: $(uname -m)"
                exit 1
                ;;
        esac

        # 获取最新版本的 Go 下载链接
        local go_version
        go_version=$(curl -sL "https://golang.org/VERSION?m=text")
        local go_download_url="https://go.dev/dl/$go_version.linux-$go_arch.tar.gz"

        # 假定 wget 已经安装，直接下载安装包
        wget -c "$go_download_url" -O - | tar -xz -C /usr/local
        echo 'export PATH=$PATH:/usr/local/go/bin' |  tee -a /etc/profile
        source /etc/profile
        go version
        
        echo "Go 已安装"
    else
        echo "Go 已经安装，跳过安装步骤。"
    fi
}

#编译安装sing-box
function compile_install_sing_box() {
    local go_install_command="go install -v -tags \
with_quic,\
with_grpc,\
with_dhcp,\
with_wireguard,\
with_shadowsocksr,\
with_ech,\
with_utls,\
with_reality_server,\
with_acme,\
with_clash_api,\
with_v2ray_api,\
with_gvisor,\
with_lwip \
github.com/sagernet/sing-box/cmd/sing-box@latest"

    echo "正在编译安装 sing-box，请稍候..."
    $go_install_command

    if [[ $? -eq 0 ]]; then
        mv ~/go/bin/sing-box /usr/local/bin/
        chmod +x /usr/local/bin/sing-box
        echo "sing-box 编译安装成功"
    else
        echo "sing-box 编译安装失败"
        exit 1
    fi
}

# 下载并安装最新的 Sing-Box 版本
function install_latest_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url

    # 根据 VPS 架构确定合适的下载 URL
    case $arch in
        x86_64)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64.tar.gz")
            ;;
        armv7l)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-armv7.tar.gz")
            ;;
        aarch64)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-arm64.tar.gz")
            ;;
        amd64v3)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64v3.tar.gz")
            ;;
        *)
            echo -e "${RED}不支持的架构：$arch${NC}"
            return 1
            ;;
    esac

    # 下载并安装 Sing-Box
    if [ -n "$download_url" ]; then
        echo "正在下载 Sing-Box..."
        curl -L -o sing-box.tar.gz "$download_url"
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz

        # 赋予可执行权限
        chmod +x /usr/local/bin/sing-box

        echo "Sing-Box 安装成功！"
    else
        echo -e "${RED}无法获取 Sing-Box 的下载 URL。${NC}"
        return 1
    fi
}

# 函数：编译安装 Caddy
install_caddy() {
    # 安装 xcaddy 工具
    echo "安装 xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

    # 编译安装 Caddy
    echo "编译安装 Caddy..."
    ~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive

    # 添加网络绑定权限
    echo "设置网络绑定权限..."
    setcap cap_net_bind_service=+ep ./caddy

    # 移动 Caddy 到 /usr/bin/
    echo "移动 Caddy 到 /usr/bin/..."
    mv caddy /usr/bin/

    echo "Caddy 安装完成。"
}

# 函数：自动获取并下载最新版的 TUIC 程序
download_tuic() {
    local repo="EAimTY/tuic"
    local arch=$(uname -m)

    case "$arch" in
        x86_64)
            arch="x86_64-unknown-linux-gnu"
            ;;
        i686)
            arch="i686-unknown-linux-gnu"
            ;;
        aarch64)
            arch="aarch64-unknown-linux-gnu"
            ;;
        armv7l)
            arch="armv7-unknown-linux-gnueabihf"
            ;;
        *)
            echo "不支持的架构: $arch"
            exit 1
            ;;
    esac

    local releases_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -sL "$releases_url" | grep -Eo "https://github.com/[^[:space:]]+/releases/download/[^[:space:]]+$arch" | head -1)

    if [ -z "$download_url" ]; then
        echo "获取最新版 TUIC 程序下载链接失败。"
        exit 1
    fi

    echo "正在下载最新版 TUIC 程序..."
    wget -qO /usr/local/bin/tuic "$download_url"

    if [ $? -ne 0 ]; then
        echo "下载 TUIC 程序失败。"
        exit 1
    fi

    # 赋予可执行权限
    echo "赋予可执行权限..."
    chmod +x /usr/local/bin/tuic

    echo "TUIC 程序下载并安装完成。"
}

# 配置 sing-box 开机自启服务
function configure_sing_box_service() {
    echo "配置 sing-box 开机自启服务..."
    local service_file="/etc/systemd/system/sing-box.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    
       local service_config='[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=1800s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "sing-box 开机自启动服务已配置。"
        systemctl daemon-reload
}

# 函数：配置 Caddy 自启动服务
configure_caddy_service() {
    echo "配置 Caddy 开机自启动服务..."
    local service_file="/etc/systemd/system/caddy.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi

        local service_config='[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/caddy run --environ --config /usr/local/etc/caddy/caddy.json
ExecReload=/usr/bin/caddy reload --config /usr/local/etc/caddy/caddy.json
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "Caddy 开机自启动服务已配置。"
}

# 配置tuic开机自启服务
function configure_tuic_service() {
    echo "配置TUIC开机自启服务..."
    local service_file="/etc/systemd/system/tuic.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    
        local service_config='[Unit]
Description=tuic service
Documentation=https://github.com/EAimTY/tuic
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/usr/local/etc/tuic/
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/tuic -c /usr/local/etc/tuic/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "TUIC 开机自启动服务已配置。"
}

# 函数：读取监听端口
function set_listen_port() {
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
    \"level\": \"info\",
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

# 函数：生成随机用户名
generate_caddy_auth_user() {
    read -p "请输入用户名（默认自动生成）: " user_input

    if [[ -z $user_input ]]; then
        auth_user=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
    else
        auth_user=$user_input
    fi

    echo "用户名: $auth_user"
}


# 函数：生成随机密码
generate_caddy_auth_pass() {
    read -p "请输入密码（默认自动生成）: " pass_input

    if [[ -z $pass_input ]]; then
        auth_pass=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
    else
        auth_pass=$pass_input
    fi

    echo "密码: $auth_pass"
}


# 函数：获取用户输入的伪装网址
get_caddy_fake_site() {
    while true; do
        read -p "请输入伪装网址（默认: www.fan-2000.com）: " fake_site
        fake_site=${fake_site:-"www.fan-2000.com"}

        # Validate the fake site URL
        if curl --output /dev/null --silent --head --fail "$fake_site"; then
            echo "伪装网址: $fake_site"
            break
        else
            echo "伪装网址无效或不可用，请重新输入。"
        fi
    done
}


# 函数：获取用户输入的域名，如果域名未绑定本机 IP，则要求重新输入
get_caddy_domain() {
    read -p "请输入域名（用于自动申请证书）: " domain
    while true; do
        if [[ -z $domain ]]; then
            echo "域名不能为空，请重新输入。"
        else
            if ping -c 1 $domain >/dev/null 2>&1; then
                break
            else
                echo "域名未绑定本机 IP，请重新输入。"
            fi
        fi
        read -p "请输入域名（用于自动申请证书）: " domain
    done

    echo "域名: $domain"
}

# 函数：创建 Caddy 配置文件
create_caddy_config() {
    local config_file="/usr/local/etc/caddy/caddy.json"

    echo "{
  \"apps\": {
    \"http\": {
      \"servers\": {
        \"https\": {
          \"listen\": [\":$listen_port\"],
          \"routes\": [
            {
              \"handle\": [
                {
                  \"handler\": \"forward_proxy\",
                  \"auth_user_deprecated\": \"$auth_user\",
                  \"auth_pass_deprecated\": \"$auth_pass\",
                  \"hide_ip\": true,
                  \"hide_via\": true,
                  \"probe_resistance\": {}
                }
              ]
            },
            {
              \"handle\": [
                {
                  \"handler\": \"headers\",
                  \"response\": {
                    \"set\": {
                      \"Strict-Transport-Security\": [\"max-age=31536000; includeSubDomains; preload\"]
                    }
                  }
                },
                {
                  \"handler\": \"reverse_proxy\",
                  \"headers\": {
                    \"request\": {
                      \"set\": {
                        \"Host\": [
                          \"{http.reverse_proxy.upstream.hostport}\"
                        ],
                        \"X-Forwarded-Host\": [\"{http.request.host}\"]
                      }
                    }
                  },
                  \"transport\": {
                    \"protocol\": \"http\",
                    \"tls\": {}
                  },
                  \"upstreams\": [
                    {\"dial\": \"$fake_site:443\"}
                  ]
                }
              ]
            }
          ],
          \"tls_connection_policies\": [
            {
              \"match\": {
                \"sni\": [\"$domain\"]
              },
              \"protocol_min\": \"tls1.2\",
              \"protocol_max\": \"tls1.2\",
              \"cipher_suites\": [\"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\"],
              \"curves\": [\"secp521r1\",\"secp384r1\",\"secp256r1\"]
            }
          ],
          \"protocols\": [\"h1\",\"h2\"]
        }
      }
    },
    \"tls\": {
      \"certificates\": {
        \"automate\": [\"$domain\"]
      },
      \"automation\": {
        \"policies\": [
          {
            \"issuers\": [
              {
                \"module\": \"acme\"
              }
            ]
          }
        ]
      }
    }
  }
}" > "$config_file"

    echo "配置文件 $config_file 写入成功。"
}

#函数：测试 caddy 配置文件
test_caddy_config() {
    echo "测试 Caddy 配置是否正确..."
    local output
    local caddy_pid

    # 运行Caddy并捕获输出
    output=$(timeout 15 /usr/bin/caddy run --environ --config /usr/local/etc/caddy/caddy.json 2>&1 &)
    caddy_pid=$!

    # 等待Caddy进程完成或超时
    wait $caddy_pid 2>/dev/null

    # 检查输出中是否包含错误提示
    if echo "$output" | grep -i "error"; then
        echo -e "${RED}Caddy 配置测试未通过，请检查配置文件${NC}"
        echo "$output" | grep -i "error" --color=always  # 输出包含错误的行，并以红色高亮显示
    else
        echo -e "${GREEN}Caddy 配置测试通过${NC}"
    fi
}

# 自动生成UUID
function tuic_generate_uuid() {
    if [[ -n $(command -v uuidgen) ]]; then
        uuid=$(uuidgen)
    elif [[ -n $(command -v uuid) ]]; then
        uuid=$(uuid -v 4)
    else
        echo -e "${RED}错误：无法生成UUID，请手动设置。${NC}"
        exit 1
    fi
    echo -e "${GREEN}生成的UUID为：$uuid${NC}"
}

# 设置密码
function tuic_set_password() {
    read -p "请输入密码（默认随机生成）: " password

    # 如果密码为空，则随机生成一个密码
    if [[ -z "$password" ]]; then
        password=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 12 | head -n 1)
        echo -e "${GREEN}生成的密码为：$password${NC}"
    fi
}

# 添加多用户
function tuic_add_multiple_users() {
    while true; do
        read -p "是否继续添加用户？(Y/N): " add_multiple_users

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            # 自动生成UUID
            tuic_generate_uuid

            # 设置密码
            tuic_set_password

            # 将UUID和密码添加到用户列表中
            users+=",\n\"$uuid\": \"$password\""
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
        fi
    done
}

# 设置证书和私钥路径
function set_certificate_and_private_key() {
    while true; do
        read -p "请输入证书路径 (默认/etc/ssl/private/cert.crt): " certificate_path
        certificate_path=${certificate_path:-"/etc/ssl/private/cert.crt"}

        if [[ "$certificate_path" != "/etc/ssl/private/cert.crt" && ! -f "$certificate_path" ]]; then
            echo -e "${RED}错误：证书文件不存在，请重新输入。${NC}"
        else
            break
        fi
    done

    while true; do
        read -p "请输入私钥路径 (默认/etc/ssl/private/private.key): " private_key_path
        private_key_path=${private_key_path:-"/etc/ssl/private/private.key"}

        if [[ "$private_key_path" != "/etc/ssl/private/private.key" && ! -f "$private_key_path" ]]; then
            echo -e "${RED}错误：私钥文件不存在，请重新输入。${NC}"
        else
            break
        fi
    done
}

# 设置拥塞控制算法
function set_congestion_control() {
    local default_congestion_control="bbr"

    while true; do
        read -p "请选择拥塞控制算法 (默认$default_congestion_control):
 [1]. bbr
 [2]. cubic
 [3]. new_reno
请输入对应的数字: " congestion_control

        case $congestion_control in
            1)
                congestion_control="bbr"
                break
                ;;
            2)
                congestion_control="cubic"
                break
                ;;
            3)
                congestion_control="new_reno"
                break
                ;;
            "")
                congestion_control=$default_congestion_control
                break
                ;;
            *)
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
                ;;
        esac
    done
}

# 生成tuic的JSON配置文件
function generate_tuic_config() {
    local config_file="/usr/local/etc/tuic/config.json"
    local users=""
    local certificate=""
    local private_key=""
    
    echo "生成tuic的JSON配置文件..."

    # 设置监听端口
    set_listen_port

    # 自动生成UUID
    tuic_generate_uuid

    # 设置密码
    tuic_set_password

    # 将UUID和密码添加到用户列表中
    users="\"$uuid\": \"$password\""

    # 添加多用户
    tuic_add_multiple_users

    # 格式化用户列表
    users=$(echo -e "$users" | sed -e 's/^/        /')

    # 配置证书和私钥路径
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    # 设置拥塞控制算法
    set_congestion_control

    # 生成tuic配置文件
    echo "{
    \"server\": \"[::]:$listen_port\",
    \"users\": {
$users
    },
    \"certificate\": \"$certificate_path\",
    \"private_key\": \"$private_key_path\",
    \"congestion_control\": \"$congestion_control\",
    \"alpn\": [\"h3\", \"spdy/3.1\"],
    \"udp_relay_ipv6\": true,
    \"zero_rtt_handshake\": false,
    \"dual_stack\": true,
    \"auth_timeout\": \"3s\",
    \"task_negotiation_timeout\": \"3s\",
    \"max_idle_time\": \"10s\",
    \"max_external_packet_size\": 1500,
    \"send_window\": 16777216,
    \"receive_window\": 8388608,
    \"gc_interval\": \"3s\",
    \"gc_lifetime\": \"15s\",
    \"log_level\": \"warn\"
}" > "$config_file"
}

# 询问证书来源选择
function ask_certificate_option() {
    while true; do
        read -p "请选择证书来源：
 [1]. 自动申请证书
 [2]. 自备证书
请输入对应的数字: " certificate_option

        case $certificate_option in
            1)
                echo "已选择自动申请证书。"
                tuic_apply_certificate
                break
                ;;
            2)
                echo "已选择自备证书。"
                break
                ;;

            *)
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
                ;;
        esac
    done
}

# 申请证书
function tuic_apply_certificate() {
    local domain

    # 验证域名
    while true; do
        read -p "请输入您的域名: " domain

        # 检查域名是否绑定本机IP
        if ping -c 1 "$domain" &>/dev/null; then
            break
        else
            echo -e "${RED}错误：域名未解析或输入错误，请重新输入。${NC}"
        fi
    done
    
    # 安装 acme
    echo "安装 acme..."
    curl https://get.acme.sh | sh 
    alias acme.sh=~/.acme.sh/acme.sh
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt 

    # 申请证书
    echo "申请证书..."
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --webroot /home/wwwroot/html 

    # 安装证书
    echo "安装证书..."
    certificate_path=$(~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --key-file "$private_key_path" --fullchain-file "$certificate_path")

    set_certificate_path="$certificate_path"
    set_private_key_path="$private_key_path"
}

# 显示 tuic 配置信息
function display_tuic_config() {
    local config_file="/usr/local/etc/tuic/config.json"
echo -e "${CYAN}TUIC节点配置信息：${NC}"    
echo -e "${CYAN}==================================================================${NC}" 
    echo "监听端口: $(jq -r '.server' "$config_file" | sed 's/\[::\]://')"
echo -e "${CYAN}------------------------------------------------------------------${NC}" 
    echo "UUID和密码列表:"
    jq -r '.users | to_entries[] | "UUID:\(.key)\t密码:\(.value)"' "$config_file"
echo -e "${CYAN}------------------------------------------------------------------${NC}" 
    echo "拥塞控制算法: $(jq -r '.congestion_control' "$config_file")"
echo -e "${CYAN}------------------------------------------------------------------${NC}" 
    echo "ALPN协议:$(jq -r '.alpn[] | select(. != "")' "$config_file" | sed ':a;N;$!ba;s/\n/, /g')"
echo -e "${CYAN}==================================================================${NC}"    
}

# 函数：读取上行速度
function read_up_speed() {
    while true; do
        read -p "请输入上行速度 (默认50): " up_mbps
        up_mbps=${up_mbps:-50}

        if [[ $up_mbps =~ ^[0-9]+$ ]]; then
            echo "上行速度设置成功：$up_mbps Mbps"
            break
        else
            echo "错误：请输入数字作为上行速度。"
        fi
    done
}

# 函数：读取下行速度
function read_down_speed() {
    while true; do
        read -p "请输入下行速度 (默认100): " down_mbps
        down_mbps=${down_mbps:-100}

        if [[ $down_mbps =~ ^[0-9]+$ ]]; then
            echo "下行速度设置成功：$down_mbps Mbps"
            break
        else
            echo "错误：请输入数字作为下行速度。"
        fi
    done
}

# 函数：读取认证密码
function read_auth_password() {
    read -p "请输入认证密码 (默认随机生成): " auth_password
    auth_password=${auth_password:-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)}
    echo "认证密码设置成功：$auth_password"
}

# 函数：读取用户信息
function read_users() {
    users="[
        {
          \"auth_str\": \"$auth_password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            read_auth_password
            users+=",
        {
          \"auth_str\": \"$auth_password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo "无效的输入，请重新输入。"
        fi
    done

    users+=$'\n      ]'
}


# 函数：验证域名解析
function validate_domain() {
    while true; do
        read -p "请输入您的域名: " domain

        if ping -c 1 "$domain" &>/dev/null; then
            break
        else
            echo "错误：域名未解析或输入错误，请重新输入。"
        fi
    done
}

function generate_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local certificate=""
    local private_key=""

    echo "生成 Hysteria 配置文件..."
    
    set_listen_port
    read_up_speed
    read_down_speed
    read_auth_password
    read_users
    validate_domain
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    # 生成配置文件
    echo "{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"hysteria\",
      \"tag\": \"hysteria-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"sniff\": true,
      \"sniff_override_destination\": true,
      \"up_mbps\": $up_mbps,
      \"down_mbps\": $down_mbps,
      \"users\": $users,
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"$domain\",
        \"alpn\": [
          \"h3\"
        ],
        \"min_version\": \"1.2\",
        \"max_version\": \"1.3\",
        \"certificate_path\": \"$certificate_path\",
        \"key_path\": \"$private_key_path\"
      }
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
}

# 函数：显示配置信息
function display_Hysteria_config_info() {
    echo -e "配置信息如下："
    echo "域名：$domain"
    echo "监听端口：$listen_port"
    echo "上行速度：${up_mbps}Mbps"
    echo "下行速度：${down_mbps}Mbps"
    echo "用户密码："

    # 提取并显示每个用户的密码
    local user_count=$(echo "$users" | jq length)
    for ((i = 0; i < user_count; i++)); do
        local auth_str=$(echo "$users" | jq -r ".[$i].auth_str")
        echo "用户$i: $auth_str"
    done
}

# 设置用户名
function set_shadowtls_username() {
    read -p "$(echo -e "${CYAN}请输入用户名 (默认随机生成): ${NC}")" new_username
    username=${new_username:-$(generate_shadowtls_random_username)}
    echo -e "${GREEN}用户名: $username${NC}"
}

# 生成随机用户名
function generate_shadowtls_random_username() {
    local username=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
    echo "$username"
}

# 生成 ShadowTLS 密码
function generate_shadowtls_password() {
    read -p "$(echo -e "${CYAN}请选择 Shadowsocks 加密方式：
1. 2022-blake3-chacha20-poly1305
2. 2022-blake3-aes-256-gcm
3. 2022-blake3-aes-128-gcm
请输入对应的数字 (默认1): ${NC}")" encryption_choice
    encryption_choice=${encryption_choice:-1}

    case $encryption_choice in
        1)
            ss_method="2022-blake3-chacha20-poly1305"
            shadowtls_password=$(openssl rand -base64 32)
            ss_password=$(openssl rand -base64 32)
            ;;
        2)
            ss_method="2022-blake3-aes-256-gcm"
            shadowtls_password=$(openssl rand -base64 32)
            ss_password=$(openssl rand -base64 32)
            ;;
        3)
            ss_method="2022-blake3-aes-128-gcm"
            shadowtls_password=$(openssl rand -base64 16)
            ss_password=$(openssl rand -base64 16)
            ;;
        *)
            echo -e "${RED}无效的选择，使用默认加密方式。${NC}"
            ss_method="2022-blake3-chacha20-poly1305"
            shadowtls_password=$(openssl rand -base64 32)
            ss_password=$(openssl rand -base64 32)
            ;;
    esac

    echo -e "${GREEN}加密方式: $ss_method${NC}"
}

# 添加用户
function add_shadowtls_user() {
    local user_password=""
    if [[ $encryption_choice == 1 || $encryption_choice == 2 ]]; then
        user_password=$(openssl rand -base64 32)
    elif [[ $encryption_choice == 3 ]]; then
        user_password=$(openssl rand -base64 16)
    fi

    read -p "$(echo -e "${CYAN}请输入用户名 (默认随机生成): ${NC}")" new_username
    local new_user=${new_username:-$(generate_shadowtls_random_username)}

    users+=",{
      \"name\": \"$new_user\",
      \"password\": \"$user_password\"
    }"

    echo -e "${GREEN}用户名: $new_user${NC}"
    echo -e "${GREEN}ShadowTLS 密码: $user_password${NC}"
}

# 设置握手服务器地址
function set_shadowtls_handshake_server() {
    local handshake_server=""
    local openssl_output=""

    read -p "$(echo -e "${CYAN}请输入握手服务器地址 (默认www.apple.com): ${NC}")" handshake_server
    handshake_server=${handshake_server:-www.apple.com}

    # 验证握手服务器是否支持TLS 1.3
    echo "正在验证握手服务器支持的TLS版本..."

    local is_supported="false"

    if command -v openssl >/dev/null 2>&1; then
        local openssl_version=$(openssl version)

        if [[ $openssl_version == *"OpenSSL"* ]]; then
            while true; do
                openssl_output=$(timeout 90s openssl s_client -connect "$handshake_server:443" -tls1_3 2>&1)

                if [[ $openssl_output == *"Protocol  : TLSv1.3"* ]]; then
                    is_supported="true"
                    echo -e "${GREEN}握手服务器支持TLS 1.3。${NC}"
                    break
                else
                    echo -e "${RED}错误：握手服务器不支持TLS 1.3，请重新输入握手服务器地址。${NC}"
                    read -p "$(echo -e "${CYAN}请输入握手服务器地址 (默认www.apple.com): ${NC}")" handshake_server
                    handshake_server=${handshake_server:-www.apple.com}
                    echo "正在验证握手服务器支持的TLS版本..."
                fi
            done
        fi
    fi

    if [[ $is_supported == "false" ]]; then
        echo -e "${YELLOW}警告：无法验证握手服务器支持的TLS版本。请确保握手服务器支持TLS 1.3。${NC}"
    fi
    handshake_server_global=$handshake_server
}

# 配置 sing-box 配置文件
function configure_shadowtls_config_file() {
    local config_file="/usr/local/etc/sing-box/config.json"

    set_listen_port
    set_shadowtls_username
    generate_shadowtls_password

    local users="{
          \"name\": \"$username\",
          \"password\": \"$shadowtls_password\"
        }"

    local add_multiple_users="Y"

    while [[ $add_multiple_users == [Yy] ]]; do
        read -p "$(echo -e "${CYAN}是否添加多用户？(Y/N，默认为N): ${NC}")" add_multiple_users

        if [[ $add_multiple_users == [Yy] ]]; then
            add_shadowtls_user
        fi
    done

    set_shadowtls_handshake_server

    # 写入配置文件
    echo "{
  \"inbounds\": [
    {
      \"type\": \"shadowtls\",
      \"tag\": \"st-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"version\": 3,
      \"users\": [
        $users
      ],
      \"handshake\": {
        \"server\": \"$handshake_server_global\",
        \"server_port\": 443
      },
      \"strict_mode\": true,
      \"detour\": \"ss-in\"
    },
    {
      \"type\": \"shadowsocks\",
      \"tag\": \"ss-in\",
      \"listen\": \"127.0.0.1\",
      \"network\": \"tcp\",
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
}" | jq '.' > "$config_file"
}

# 显示 sing-box 配置信息
function display_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    echo "================================================================"
    echo -e "${CYAN}ShadowTLS 节点配置信息：${NC}"
    echo "----------------------------------------------------------------"
    echo -e "${GREEN}监听端口: $listen_port${NC}"
    echo "----------------------------------------------------------------"
    jq -r '.inbounds[0].users[] | "ShadowTLS 密码: \(.password)"' "$config_file" | while IFS= read -r line; do
    echo -e "${GREEN}$line${NC}"
done  
    echo "----------------------------------------------------------------"  
    echo -e "${GREEN}Shadowsocks 密码: $ss_password${NC}"
    echo "================================================================"
}

# 重启 sing-box 服务
function restart_sing_box_service() {
    echo "重启 sing-box 服务..."
    systemctl restart sing-box

    if [[ $? -eq 0 ]]; then
        echo "sing-box 服务已重启。"
    else
        echo -e "${RED}重启 sing-box 服务失败。${NC}"
    fi

    systemctl status sing-box
}

# 重启 naiveproxy 服务
function restart_naiveproxy_service() {
    echo "重启 naiveproxy 服务..."
    systemctl reload caddy

    if [[ $? -eq 0 ]]; then
        echo "naiveproxy 服务已重启。"
    else
        echo -e "${RED}重启 sing-box 服务失败。${NC}"
    fi

    systemctl status caddy
}

# 重启 TUIC
function restart_tuic() {
    echo "重启 TUIC 服务..."
    systemctl restart tuic.service
    echo -e "${GREEN}TUIC 已重启...${NC}"
    systemctl status tuic.service   
}

# 卸载 sing-box
function uninstall_sing_box() {
    echo "开始卸载 sing-box..."

    systemctl stop sing-box

    # 删除文件和文件夹
    echo "删除文件和文件夹..."
    rm -rf /usr/local/bin/sing-box
    rm -rf /usr/local/etc/sing-box
    rm -rf /etc/systemd/system/sing-box.service
    systemctl daemon-reload

    echo "sing-box 卸载完成。"
}

# 函数：卸载 NaiveProxy
function uninstall_naiveproxy() {
    echo "开始卸载 NaiveProxy..."
    systemctl stop caddy
    systemctl disable caddy
    rm /etc/systemd/system/caddy.service
    rm /usr/local/etc/caddy/caddy.json
    rm /usr/bin/caddy
    systemctl daemon-reload
    echo "NaiveProxy 卸载完成。"
}

# 卸载 TUIC
function uninstall_tuic() {
    echo "卸载 TUIC 服务..."
    systemctl stop tuic.service
    systemctl disable tuic.service
    rm /etc/systemd/system/tuic.service
    rm /usr/local/etc/tuic/config.json
    rm /usr/local/bin/tuic
    echo -e "${GREEN}TUIC 服务已卸载...${NC}"
}

function Direct_extract_config_info() {
    local local_ip
    local_ip=$(curl -s http://ifconfig.me)

    echo "========= 安装完成 ========="
    echo "本机 IP 地址: $local_ip"
    echo "监听端口: $listen_port"
    echo "目标地址: $override_address"
    echo "目标端口: $override_port"
}

function Shadowsocks_extract_config_info() {
    local local_ip
    local_ip=$(curl -s http://ifconfig.me)

    echo "========= 配置完成 ========="
    echo "本机 IP 地址: $local_ip"
    echo "监听端口: $listen_port"
    echo "加密方式: $ss_method"
    echo "密码: $ss_password"
}

function NaiveProxy_extract_config_info() {

    echo -e "${GREEN}NaiveProxy节点配置信息:${NC}"
    echo -e "监听端口: ${GREEN}$listen_port${NC}"
    echo -e "用 户 名: ${GREEN}$auth_user${NC}"
    echo -e "密    码: ${GREEN}$auth_pass${NC}"
    echo -e "域    名: ${GREEN}$domain${NC}"   
}

function Direct_install() {
    install_dependencies
    enable_bbr
    select_sing_box_install_option
    configure_sing_box_service
    check_sing_box_folder
    set_listen_port
    Direct_override_address
    Direct_override_port
    Direct_write_config_file
    check_firewall_configuration    
    systemctl enable sing-box   
    systemctl start sing-box
    Direct_extract_config_info
}

function Shadowsocks_install() {
    install_dependencies
    enable_bbr
    select_sing_box_install_option
    configure_sing_box_service
    check_sing_box_folder
    set_listen_port
    ss_encryption_method
    ss_write_sing_box_config
    check_firewall_configuration    
    systemctl enable sing-box   
    systemctl start sing-box
    Shadowsocks_extract_config_info
}

function NaiveProxy_install() {
    install_dependencies
    enable_bbr
    install_go
    install_caddy
    check_caddy_folder
    set_listen_port
    generate_caddy_auth_user
    generate_caddy_auth_pass
    get_caddy_fake_site
    get_caddy_domain    
    create_caddy_config
    check_firewall_configuration    
    test_caddy_config
    configure_caddy_service
    systemctl daemon-reload 
    systemctl enable caddy
    systemctl start caddy
    systemctl reload caddy
    NaiveProxy_extract_config_info
}

function install_tuic_Serve() {
    install_dependencies
    enable_bbr
    create_tuic_directory   
    download_tuic
    generate_tuic_config
    check_firewall_configuration 
    ask_certificate_option
    configure_tuic_service
    systemctl daemon-reload
    systemctl enable tuic.service
    systemctl start tuic.service
    systemctl restart tuic.service
    display_tuic_config
}

function Hysteria_install() {
    install_dependencies
    enable_bbr
    select_sing_box_install_option      
    check_sing_box_folder
    generate_Hysteria_config
    check_firewall_configuration 
    ask_certificate_option 
    configure_sing_box_service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    display_Hysteria_config_info
}

function shadowtls_install() {
    install_dependencies
    enable_bbr
    select_sing_box_install_option      
    check_sing_box_folder
    configure_shadowtls_config_file
    check_firewall_configuration      
    configure_sing_box_service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    display_shadowtls_config
}

# 主菜单
function main_menu() {
        echo -e "${GREEN}               ------------------------------------------------------------------------------------ ${NC}"
        echo -e "${GREEN}               |                          欢迎使用 Reality 安装程序                               |${NC}"
        echo -e "${GREEN}               |                      项目地址:https://github.com/TinrLin                         |${NC}"
        echo -e "${GREEN}               ------------------------------------------------------------------------------------${NC}"
        echo -e "${CYAN}请选择要执行的操作：${NC}"
        echo -e "  ${CYAN}[01]. vless+vision+reality${NC}"
        echo -e "  ${CYAN}[02]. vless+grpc+reality${NC}"
        echo -e "  ${CYAN}[03]. vless+h2+reality${NC}"
        echo -e "  ${CYAN}[04]. ShadowTLS V3${NC}"
        echo -e "  ${CYAN}[05]. Shadowsocks${NC}"
        echo -e "  ${CYAN}[06]. NaiveProxy${NC}"
        echo -e "  ${CYAN}[07]. TUIC V5${NC}"
        echo -e "  ${CYAN}[08]. Hysteria${NC}"
        echo -e "  ${CYAN}[09]. Direct 流量中转${NC}"
        echo -e "  ${CYAN}[10]. 重启 sing-box 服务${NC}"
        echo -e "  ${CYAN}[11]. 重启 Caddy 服务${NC}"
        echo -e "  ${CYAN}[12]. 重启 TUIC 服务${NC}"
        echo -e "  ${CYAN}[13]. 卸载 sing-box 服务${NC}"
        echo -e "  ${CYAN}[14]. 卸载 Caddy 服务${NC}"
        echo -e "  ${CYAN}[15]. 卸载 TUIC 服务${NC}"
        echo -e "  ${CYAN}[00]. 退出脚本${NC}"

        local choice
        read -p "请选择 [0-15]: " choice

        case $choice in
            1)
                inst
                ;;
            2)
                stop
                ;;
            3)
                resta
                ;;
            4)
                shadowtls_install
                ;;
            5)
                Shadowsocks_install
                ;;
            6)
                NaiveProxy_install
                ;;
            7)
                install_tuic_Serve
                ;;                
            8)
                Hysteria_install
                ;;

            9)
                Direct_install
                ;;
            10)
                restart_naiveproxy_service
                ;;
            11)
                restart_naiveproxy_service
                ;;
            12)
                restart_tuic
                ;;
            13)
                uninstall_sing_box
                ;;
            14)
                uninstall_naiveproxy
                ;;
            15)
                uninstall_tuic
                ;;           
            0)
                echo -e "${GREEN}感谢使用 Reality 安装脚本！再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入。${NC}"
                main_menu
                ;;
        esac
}


main_menu
