#!/usr/bin/env bash
set -euo pipefail

# ── 配置 ────────────────────────────────────────────────────
REPO="1414906463yang-hash/wx-cli"
BIN_NAME="wx"
INSTALL_DIR="/usr/local/bin"

# ── 检测平台 ────────────────────────────────────────────────
OS=$(uname -s)
ARCH=$(uname -m)

case "${OS}-${ARCH}" in
  Darwin-arm64)   PLATFORM="macos-arm64" ;;
  Darwin-x86_64)  PLATFORM="macos-x86_64" ;;
  Linux-x86_64)   PLATFORM="linux-x86_64" ;;
  Linux-aarch64)  PLATFORM="linux-arm64" ;;
  *)
    echo "不支持的平台: ${OS}-${ARCH}"
    echo "请从源码构建: git clone https://github.com/${REPO}.git && cd wx-cli && cargo build --release"
    exit 1
    ;;
esac

echo "正在获取最新版本..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$TAG" ]; then
  echo "获取版本失败，尝试从源码构建..."
  echo "git clone https://github.com/${REPO}.git && cd wx-cli && cargo build --release"
  exit 1
fi

echo "版本: ${TAG}  平台: ${PLATFORM}"

# ── 下载预编译二进制 ───────────────────────────────────────
ASSET="wx-cli-${TAG}-${PLATFORM}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# 先尝试下载预编译版本
if curl -fsSL -o "$TMP_DIR/${ASSET}" "$URL" 2>/dev/null; then
  echo "下载预编译版本: ${URL}"
  tar -xzf "$TMP_DIR/${ASSET}" -C "$TMP_DIR"
  # 查找解压后的二进制（可能在子目录中）
  BIN_PATH=$(find "$TMP_DIR" -name "wx" -type f -o -name "wx.exe" -type f | head -1)
  if [ -z "$BIN_PATH" ]; then
    echo "解压后未找到二进制，尝试源码构建..."
    BUILD_FROM_SOURCE=1
  fi
else
  echo "预编译版本不可用，尝试源码构建..."
  BUILD_FROM_SOURCE=1
fi

# ── 源码构建 ────────────────────────────────────────────────
if [ "${BUILD_FROM_SOURCE:-0}" = "1" ]; then
  echo "需要从源码构建，请确保已安装 Rust (https://rustup.rs/)"
  
  # 检查 cargo
  if ! command -v cargo &> /dev/null; then
    echo "未找到 Rust/Cargo，请先安装: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
  fi
  
  echo "克隆仓库并构建..."
  git clone "https://github.com/${REPO}.git" "$TMP_DIR/wx-cli-src"
  cd "$TMP_DIR/wx-cli-src"
  cargo build --release
  
  if [ "$OS" = "Darwin" ]; then
    BIN_PATH="$TMP_DIR/wx-cli-src/target/release/wx"
  elif [ "$OS" = "Linux" ]; then
    BIN_PATH="$TMP_DIR/wx-cli-src/target/release/wx"
  else
    BIN_PATH="$TMP_DIR/wx-cli-src/target/release/wx.exe"
  fi
  
  if [ ! -f "$BIN_PATH" ]; then
    echo "构建失败，未找到输出二进制"
    exit 1
  fi
fi

# ── 安装 ────────────────────────────────────────────────────
chmod +x "$BIN_PATH"

if [ -w "$INSTALL_DIR" ]; then
  mv "$BIN_PATH" "${INSTALL_DIR}/${BIN_NAME}"
else
  echo "需要 sudo 权限安装到 ${INSTALL_DIR}"
  sudo mv "$BIN_PATH" "${INSTALL_DIR}/${BIN_NAME}"
fi

echo ""
echo "✓ wx 已安装到 ${INSTALL_DIR}/${BIN_NAME}"
echo ""
echo "快速开始："
echo "  sudo wx init     # 首次初始化（需要微信正在运行）"
echo "  wx sessions      # 查看最近会话"
echo "  wx --help        # 查看所有命令"
