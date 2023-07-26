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
    local listen_port=$(jq -r '.inbounds[0].listen_port' /usr/local/etc/sing-box/config.json)
    local os_name=$(uname -s)
    local firewall

    if [[ $os_name == "Linux" ]]; then
        if command -v ufw >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then
            firewall="ufw"
        elif command -v iptables >/dev/null 2>&1 && command -v firewalld >/dev/null 2>&1; then
            firewall="iptables-firewalld"
        fi
    fi

    if [[ -z $firewall ]]; then
        echo -e "${RED}无法检测到适用的防火墙配置工具，请手动配置防火墙。${NC}"
        return
    fi

    echo "检查防火墙配置..."

    case $firewall in
        ufw)
            if ! ufw status | grep -q "Status: active"; then
                ufw enable
            fi

            if ! ufw status | grep -q "$listen_port"; then
                ufw allow "$listen_port"
            fi

            echo "防火墙配置已更新。"
            ;;
        iptables-firewalld)
            if command -v iptables >/dev/null 2>&1; then
                if ! iptables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                    iptables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT
                fi

                iptables-save > /etc/sysconfig/iptables

                echo "iptables防火墙配置已更新。"
            fi

            if command -v firewalld >/dev/null 2>&1; then
                if ! firewall-cmd --state | grep -q "running"; then
                    systemctl start firewalld
                    systemctl enable firewalld
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp"; then
                    firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp"; then
                    firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent
                fi

                firewall-cmd --reload

                echo "firewalld防火墙配置已更新。"
            fi
            ;;
    esac
}

# 检查是否存在文件夹，不存在则创建
function check_and_create_folder() {
    local folder=$1
    if [ ! -d "$folder" ]; then
        mkdir -p "$folder"
        echo -e "${GREEN}创建 $folder 成功。${NC}"
    else
        echo -e "${YELLOW}$folder 已存在，跳过创建。${NC}"
    fi
}

# 检查是否存在文件，不存在则创建
function check_and_create_file() {
    local file=$1
    if [ ! -f "$file" ]; then
        touch "$file"
        echo -e "${GREEN}创建 $file 成功。${NC}"
    else
        echo -e "${YELLOW}$file 已存在，跳过创建。${NC}"
    fi
}

# 函数：开启 BBR
enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "开启 BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}BBR 已开启${NC}"
    else
        echo -e "${YELLOW}BBR 已经开启，跳过配置。${NC}"
    fi
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
    sing_box_version=$(go list -m -versions github.com/sagernet/sing-box/cmd/sing-box | tail -1)

    go install -v -tags "with_dhcp@${sing_box_version},with_dhcp,with_wireguard@${sing_box_version},with_ech@${sing_box_version},with_utls@${sing_box_version},with_clash_api@${sing_box_version},with_v2ray_api@${sing_box_version},with_gvisor@${sing_box_version},with_lwip@${sing_box_version}" \
        github.com/sagernet/sing-box/cmd/sing-box@latest

    if [[ $? -eq 0 ]]; then
        cp ~/go/bin/sing-box /usr/local/bin/
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
    echo "[Unit]
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
WantedBy=multi-user.target" |  tee /etc/systemd/system/sing-box.service >/dev/null
}

# 函数：配置 Caddy 自启动服务
configure_caddy_service() {
    echo "配置 Caddy 自启动服务..."
    local service_file="/etc/systemd/system/caddy.service"

    if [[ -f $service_file ]]; then
        echo "Caddy 服务文件已存在，重新写入配置..."
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
        systemctl daemon-reload
        systemctl enable caddy
        systemctl start caddy
        systemctl reload caddy
        echo "Caddy 自启动服务已配置。"
}

