#!/bin/bash

# 1. 获取当前物理机的真实操作系统和架构 (无视已被污染的环境变量)
HOST_OS=$(go env GOHOSTOS)
HOST_ARCH=$(go env GOHOSTARCH)

echo "🔍 检测到当前宿主机环境: OS=$HOST_OS, ARCH=$HOST_ARCH"

# 2. 强制覆盖编译环境变量，确保编译出的是能在本机跑的程序
export GOOS=$HOST_OS
export GOARCH=$HOST_ARCH

# 3. 强制关闭 CGO (这是引发 Windows "%1 is not a valid Win32 application" 的元凶)
export CGO_ENABLED=0

echo "⚙️  已设置编译参数: GOOS=$GOOS, GOARCH=$GOARCH, CGO_ENABLED=$CGO_ENABLED"

# 4. (可选) 清理之前可能损坏的测试缓存
echo "🧹 清理旧缓存..."
go clean -testcache

# 5. 运行所有的 e2e 测试
echo "🚀 开始执行 E2E 测试矩阵..."
go test -v -count=1
echo "🚀 开始执行 E2E benchmark..."
go test -bench=BenchmarkH2TunnelAllProtocols -benchmem -benchtime=3s