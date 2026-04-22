#!/bin/bash

# ==========================================
# H2Tunnel 一键安装/卸载脚本
# ==========================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# ================= 参数解析 =================
ACTION=""
CUSTOM_TOKEN=""
CUSTOM_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            CUSTOM_TOKEN="$2"
            shift 2
            ;;
        --path)
            CUSTOM_PATH="$2"
            shift 2
            ;;
        install|uninstall)
            ACTION="$1"
            shift
            ;;
        *)
            echo "使用方法: $0 {install|uninstall} [--token <密钥>] [--path <路径>]"
            exit 1
            ;;
    esac
done

if [ -z "$ACTION" ]; then
    echo "使用方法: $0 {install|uninstall} [--token <密钥>] [--path <路径>]"
    exit 1
fi

# 核心变量
REPO="NNdroid/h2tunnel"
BIN_DIR="/usr/local/bin"
CONF_DIR="/usr/local/etc/h2tunnel"
BIN_NAME="h2tunnel"
BIN_PATH="$BIN_DIR/$BIN_NAME"
SERVICE_NAME="h2tunnel.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
PATH_FILE="$CONF_DIR/path.txt"
TOKEN_FILE="$CONF_DIR/token.txt"

# 必须以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ 请使用 root 权限运行此脚本 (例如: sudo ./install.sh install)${NC}"
    exit 1
fi

# ==========================================
# 卸载逻辑
# ==========================================
uninstall() {
    echo -e "${YELLOW}🗑️  正在卸载 H2Tunnel...${NC}"
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        systemctl stop $SERVICE_NAME
    fi
    if systemctl is-enabled --quiet $SERVICE_NAME; then
        systemctl disable $SERVICE_NAME
    fi
    
    rm -f $SERVICE_PATH
    systemctl daemon-reload
    
    rm -f $BIN_PATH
    
    # 强制删除配置目录及路径/密钥记录
    rm -rf $CONF_DIR
    echo -e "${GREEN}✅ 配置目录、证书、连接路径及 Token 已彻底删除。${NC}"
    
    echo -e "${GREEN}✅ 卸载完成！${NC}"
    exit 0
}

# ==========================================
# 安装/更新逻辑
# ==========================================
install() {
    # 1. 检查必备依赖
    for cmd in curl wget openssl jq; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${YELLOW}📦 正在安装必备依赖: $cmd...${NC}"
            apt-get update && apt-get install -y $cmd || yum install -y $cmd
        fi
    done

    # 2. 获取系统架构
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) GOARCH="amd64" ;;
        aarch64|arm64) GOARCH="arm64" ;;
        *) echo -e "${RED}❌ 不支持的架构: $ARCH${NC}"; exit 1 ;;
    esac

    # 3. 获取 GitHub 最新版本
    echo -e "${GREEN}🔍 正在检查 $REPO 的最新版本...${NC}"
    LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$LATEST_TAG" ]; then
        echo -e "${RED}❌ 获取最新版本失败，请检查网络或 GitHub 仓库地址。${NC}"
        exit 1
    fi

    # 4. 对比本地版本
    if [ -f "$BIN_PATH" ]; then
        LOCAL_VERSION=$($BIN_PATH version 2>/dev/null | awk '{print $NF}')
        if [ "$LOCAL_VERSION" == "$LATEST_TAG" ]; then
            echo -e "${GREEN}✅ 当前已是最新版本 ($LOCAL_VERSION)，无需操作。${NC}"
            if ! systemctl is-active --quiet $SERVICE_NAME; then
                systemctl start $SERVICE_NAME
            fi
            # 打印连接信息供用户查阅
            if [ -f "$PATH_FILE" ] && [ -f "$TOKEN_FILE" ]; then
                echo -e "当前安全路径: ${YELLOW}$(cat "$PATH_FILE")${NC}"
                echo -e "当前安全密钥: ${YELLOW}$(cat "$TOKEN_FILE")${NC}"
            fi
            exit 0
        fi
        echo -e "${YELLOW}⬆️  发现新版本: $LOCAL_VERSION -> $LATEST_TAG${NC}"
    else
        echo -e "${GREEN}⬇️  准备安装版本: $LATEST_TAG${NC}"
    fi

    # 5. 下载最新程序
    ASSET_NAME="${BIN_NAME}_${OS}_${GOARCH}"
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$ASSET_NAME"
    
    echo -e "${GREEN}📥 正在下载: $DOWNLOAD_URL${NC}"
    wget -q --show-progress -O /tmp/$ASSET_NAME "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ 下载失败，请检查对应的 Release 文件是否存在: $ASSET_NAME${NC}"
        exit 1
    fi
    
    systemctl stop $SERVICE_NAME 2>/dev/null
    mv /tmp/$ASSET_NAME $BIN_PATH
    chmod +x $BIN_PATH

    # 6. 处理配置目录与证书 (仅首次安装时生成)
    if [ ! -d "$CONF_DIR" ]; then
        echo -e "${GREEN}🔐 检测到初次安装，正在生成配置目录与自签证书...${NC}"
        mkdir -p $CONF_DIR
        
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$CONF_DIR/server.key" \
            -out "$CONF_DIR/server.crt" \
            -days 3650 \
            -subj "/C=US/ST=Washington/L=Seattle/O=Amazon.com, Inc./OU=Amazon Web Services/CN=ec2.amazonaws.com" 2>/dev/null
            
        chown -R nobody "$CONF_DIR"
        chmod 600 "$CONF_DIR/server.key"
        chmod 644 "$CONF_DIR/server.crt"
    fi

    # 🌟 7. 动态处理 Path 和 Token
    # 处理 Path
    if [ -n "$CUSTOM_PATH" ]; then
        TUNNEL_PATH="$CUSTOM_PATH"
        [[ "$TUNNEL_PATH" != /* ]] && TUNNEL_PATH="/${TUNNEL_PATH}"
        echo "$TUNNEL_PATH" > "$PATH_FILE"
        echo -e "${GREEN}🔑 使用指定的安全路径: $TUNNEL_PATH${NC}"
    elif [ -f "$PATH_FILE" ]; then
        TUNNEL_PATH=$(cat "$PATH_FILE")
    else
        TUNNEL_PATH="/"$(openssl rand -hex 16)
        echo "$TUNNEL_PATH" > "$PATH_FILE"
        echo -e "${GREEN}🔑 已生成 32 位随机安全路径: $TUNNEL_PATH${NC}"
    fi

    # 处理 Token
    if [ -n "$CUSTOM_TOKEN" ]; then
        TUNNEL_TOKEN="$CUSTOM_TOKEN"
        echo "$TUNNEL_TOKEN" > "$TOKEN_FILE"
        echo -e "${GREEN}🔑 使用指定的 Token: $TUNNEL_TOKEN${NC}"
    elif [ -f "$TOKEN_FILE" ]; then
        TUNNEL_TOKEN=$(cat "$TOKEN_FILE")
    else
        TUNNEL_TOKEN=$(openssl rand -hex 8)
        echo "$TUNNEL_TOKEN" > "$TOKEN_FILE"
        echo -e "${GREEN}🔑 已生成 16 位随机安全密钥: $TUNNEL_TOKEN${NC}"
    fi

    # 修复文件权限
    chmod 644 "$PATH_FILE" "$TOKEN_FILE" 2>/dev/null

    # 8. 配置 Systemd 服务
    echo -e "${GREEN}⚙️  正在配置 Systemd 守护进程...${NC}"
    cat > $SERVICE_PATH <<EOF
[Unit]
Description=H2Tunnel Server Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# 启动命令 (注入动态获取的路径与 Token)
ExecStart=$BIN_PATH server -listen 0.0.0.0:443 -cert $CONF_DIR/server.crt -key $CONF_DIR/server.key -path $TUNNEL_PATH -token $TUNNEL_TOKEN -local-only -loglevel warn

Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # 9. 启动服务
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME

    # 10. 打印终极安装结果
    SERVER_IP=$(curl -s ifconfig.me || echo "你的服务器IP")

    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}🎉 H2Tunnel 安装/更新成功！${NC}"
    echo -e "当前版本: ${YELLOW}$LATEST_TAG${NC}"
    echo -e "运行状态: $(systemctl is-active $SERVICE_NAME)"
    echo -e "配置路径: $CONF_DIR"
    echo -e ""
    echo -e "${YELLOW}【客户端连接信息 (请务必保存)】${NC}"
    echo -e "IP地址: ${GREEN}$SERVER_IP${NC}"
    echo -e "端口号: ${GREEN}443${NC}"
    echo -e "私密路径: ${RED}$TUNNEL_PATH${NC}  <-- 必须配置到客户端的 custom_path 中"
    echo -e "连接密钥: ${RED}$TUNNEL_TOKEN${NC}  <-- 必须配置到客户端的 token 中"
    echo -e ""
    echo -e "查看日志: ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "${GREEN}=========================================${NC}"
}

# ==========================================
# 菜单入口
# ==========================================
case "$ACTION" in
    install)
        install
        ;;
    uninstall)
        uninstall
        ;;
esac