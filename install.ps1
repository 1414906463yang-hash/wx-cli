#Requires -RunAsAdministrator
<#
.SYNOPSIS
    wx-cli 一键安装脚本 (Windows PowerShell)
.DESCRIPTION
    自动下载并安装 wx-cli 到系统 PATH。
    支持预编译二进制下载和源码构建回退。
#>

$ErrorActionPreference = "Stop"

$REPO      = "1414906463yang-hash/wx-cli"
$BIN_NAME  = "wx.exe"
$INSTALL_DIR = "$env:LOCALAPPDATA\Microsoft\WindowsApps"

# 检测平台
$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "x86_64" } else { "arm64" }
$PLATFORM = "windows-$ARCH"

Write-Host "正在获取最新版本..." -ForegroundColor Cyan

try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -UseBasicParsing
    $TAG = $release.tag_name
} catch {
    Write-Error "获取版本失败: $_"
    exit 1
}

Write-Host "版本: $TAG  平台: $PLATFORM" -ForegroundColor Green

$ASSET = "wx-cli-$TAG-$PLATFORM.zip"
$URL   = "https://github.com/$REPO/releases/download/$TAG/$ASSET"
$TMP   = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid().ToString()
New-Item -ItemType Directory -Path $TMP | Out-Null

# 尝试下载预编译版本
try {
    Write-Host "下载: $URL" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $URL -OutFile "$TMP\$ASSET" -UseBasicParsing
    Expand-Archive -Path "$TMP\$ASSET" -DestinationPath $TMP -Force
    $BIN_PATH = Get-ChildItem -Path $TMP -Recurse -Filter "wx.exe" | Select-Object -First 1
    if (-not $BIN_PATH) { throw "解压后未找到 wx.exe" }
} catch {
    Write-Host "预编译版本不可用，尝试从源码构建..." -ForegroundColor Yellow
    
    # 检查 Rust
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error @"
未找到 Rust/Cargo。请先安装 Rust:
  1. 访问 https://rustup.rs/ 下载安装器
  2. 或运行: winget install Rustlang.Rustup
"@
        exit 1
    }
    
    Write-Host "克隆仓库并构建..." -ForegroundColor Cyan
    git clone "https://github.com/$REPO.git" "$TMP\wx-cli-src"
    Set-Location "$TMP\wx-cli-src"
    cargo build --release
    
    $BIN_PATH = "$TMP\wx-cli-src\target\release\wx.exe"
    if (-not (Test-Path $BIN_PATH)) {
        Write-Error "构建失败，未找到 wx.exe"
        exit 1
    }
}

# 安装
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
}

Copy-Item -Path $BIN_PATH.FullName -Destination "$INSTALL_DIR\$BIN_NAME" -Force
Write-Host ""
Write-Host "✓ wx 已安装到 $INSTALL_DIR\$BIN_NAME" -ForegroundColor Green
Write-Host ""
Write-Host "快速开始：" -ForegroundColor Cyan
Write-Host "  wx init          # 首次初始化（管理员权限 + 微信正在运行）"
Write-Host "  wx sessions      # 查看最近会话"
Write-Host "  wx --help        # 查看所有命令"

# 清理
Remove-Item -Recurse -Force $TMP -ErrorAction SilentlyContinue
