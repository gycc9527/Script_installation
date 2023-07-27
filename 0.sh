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

    if ! command -v $dependencies &> /dev/null; then
        echo "下载并安装依赖..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y $dependencies
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y $dependencies
        elif command -v yum &> /dev/null; then
            sudo yum install -y $dependencies
        fi

        echo "依赖已安装。"
    else
        echo "依赖已经安装，跳过安装步骤。"
    fi
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
    sudo mv caddy /usr/bin/

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
    chmod +x /usr/bin/tuic

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
ExecStart=/usr/bin/tuic -c /usr/local/etc/tuic/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "TUIC 开机自启动服务已配置。"
}

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

function Direct_install() {

    install_dependencies
    enable_bbr
    select_sing_box_install_option
    configure_sing_box_service
    check_sing_box_folder
    Direct_listen_port
    Direct_override_address
    Direct_override_port
    Direct_write_config_file
    check_firewall_configuration    
    systemctl enable sing-box   
    systemctl start sing-box
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
        echo -e "  ${CYAN}[05]. NaiveProxy${NC}"
        echo -e "  ${CYAN}[06]. TUIC V5${NC}"
        echo -e "  ${CYAN}[07]. Hysteria${NC}"
        echo -e "  ${CYAN}[08]. Direct 流量中转${NC}"
        echo -e "  ${CYAN}[09]. 重启 sing-box 服务${NC}"
        echo -e "  ${CYAN}[10]. 重启 Caddy 服务${NC}"
        echo -e "  ${CYAN}[11]. 重启 TUIC 服务${NC}"
        echo -e "  ${CYAN}[12]. 卸载 sing-box 服务${NC}"
        echo -e "  ${CYAN}[13]. 卸载 Caddy 服务${NC}"
        echo -e "  ${CYAN}[14]. 卸载 TUIC 服务${NC}"
        echo -e "  ${CYAN}[00]. 退出脚本${NC}"

        local choice
        read -p "请选择 [0-14]: " choice

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
                view
                ;;
            5)
                unins
                ;;
            5)
                unin
                ;;
            6)
                unins
                ;;

            7)
                unins
                ;;
            8)
                Direct_install
                ;;
            9)
                restart_sing_box_service
                ;;
            10)
                unin
                ;;
            11)
                unin
                ;;
            12)
                uninstall_sing_box
                ;;
            13)
                unin
                ;;
            14)
                unin
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
