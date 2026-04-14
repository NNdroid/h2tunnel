#!/bin/bash

# ==========================================
# H2Tunnel 一键跨平台编译脚本
# ==========================================

# 遇到错误立即退出
set -e

# 应用名称
APP_NAME="h2tunnel"

# 输出目录 (上一级目录下的 bin 文件夹)
OUTPUT_DIR="./bin"

# 定义发版版本号
VERSION="v1.0.$(date +%Y%m%d)"

# 目标平台配置列表 (格式: GOOS/GOARCH)
PLATFORMS=(
    "linux/amd64"    # Linux x86_64 (常见服务器)
    "linux/arm64"    # Linux ARM64 (树莓派、甲骨文 ARM 机)
    "windows/amd64"  # Windows 64位
    "windows/arm64"  # Windows ARM (部分新一代笔电)
    "darwin/amd64"   # macOS Intel
    "darwin/arm64"   # macOS Apple Silicon (M1/M2/M3)
)

# 清理并创建输出目录
echo "📁 准备输出目录: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# 编译参数：
# -s: 忽略符号表
# -w: 忽略 DWARF 调试信息
# 这两个参数可以大幅减小编译后的二进制文件体积
LDFLAGS="-s -w -X 'main.Version=$VERSION'"

echo "🚀 开始跨平台编译..."
echo "----------------------------------------"


# 遍历平台列表进行编译
for PLATFORM in "${PLATFORMS[@]}"; do
    # 拆分 GOOS 和 GOARCH
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    
    # 拼接最终输出的文件名 (例如: h2tunnel_linux_amd64)
    OUTPUT_FILE="${APP_NAME}_${GOOS}_${GOARCH}"
    
    # 如果是 Windows 系统，自动加上 .exe 后缀
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_FILE="${OUTPUT_FILE}.exe"
    fi
    
    echo "⏳ 正在编译: $GOOS / $GOARCH -> $OUTPUT_FILE"
    
    # 执行编译命令
    env CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath -ldflags="$LDFLAGS" -o "$OUTPUT_DIR/$OUTPUT_FILE" .
    
    if [ $? -ne 0 ]; then
        echo "❌ 编译失败: $GOOS / $GOARCH"
        exit 1
    fi
done

echo "----------------------------------------"
echo "✅ 全部编译完成！文件已输出到: $(cd "$OUTPUT_DIR" && pwd)"
ls -lh "$OUTPUT_DIR"