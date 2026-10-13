#!/usr/bin/env bash
# Shell One-Line Installer & Updater for `p` (Linux & macOS)
set -euo pipefail

echo "==> Mengunduh dan memasang 'p' versi terbaru..."

REPO="n0z0/p"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64)
        ASSET_PATTERN="x86_64-unknown-linux-musl.tar.gz"
        ;;
      aarch64|arm64)
        ASSET_PATTERN="aarch64-unknown-linux-musl.tar.gz"
        ;;
      *)
        echo "[-] Arsitektur tidak didukung: $ARCH ($OS)"
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      x86_64)
        ASSET_PATTERN="x86_64-apple-darwin.tar.gz"
        ;;
      arm64|aarch64)
        ASSET_PATTERN="aarch64-apple-darwin.tar.gz"
        ;;
      *)
        echo "[-] Arsitektur tidak didukung: $ARCH ($OS)"
        exit 1
        ;;
    esac
    ;;
  *)
    echo "[-] Sistem Operasi tidak didukung oleh script ini: $OS"
    exit 1
    ;;
esac

# Ambil metadata rilis terbaru dari GitHub API
RELEASE_DATA=$(curl -sSL -H "User-Agent: curl" "${API_URL}")
TAG_NAME=$(echo "$RELEASE_DATA" | grep -m1 '"tag_name":' | cut -d '"' -f 4)

if [ -z "$TAG_NAME" ]; then
  echo "[-] Gagal mendeteksi tag rilis terbaru dari GitHub API"
  exit 1
fi

echo "[+] Versi terbaru ditemukan: $TAG_NAME ($OS $ARCH)"

DOWNLOAD_URL=$(echo "$RELEASE_DATA" | grep "browser_download_url" | grep "$ASSET_PATTERN" | head -n 1 | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
  echo "[-] Asset binary untuk $ASSET_PATTERN tidak ditemukan pada rilis $TAG_NAME"
  exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[+] Mengunduh dari $DOWNLOAD_URL ..."
curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/p-archive.tar.gz"

tar -xzf "$TMP_DIR/p-archive.tar.gz" -C "$TMP_DIR"

BIN_PATH=$(find "$TMP_DIR" -type f -name "p" | head -n 1)
if [ -z "$BIN_PATH" ]; then
  echo "[-] Biner 'p' tidak ditemukan di dalam paket unduhan"
  exit 1
fi

# Tentukan direktori instalasi
if [ "$(id -u)" -eq 0 ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

cp "$BIN_PATH" "$INSTALL_DIR/p"
chmod +x "$INSTALL_DIR/p"

# Cek PATH jika menggunakan ~/.local/bin
if [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
  if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    SHELL_PROFILE=""
    if [ -n "${ZSH_VERSION:-}" ] || [ -f "$HOME/.zshrc" ]; then
      SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
      SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.profile" ]; then
      SHELL_PROFILE="$HOME/.profile"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
      if ! grep -q '\.local/bin' "$SHELL_PROFILE" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_PROFILE"
        echo "[+] Menambahkan ~/.local/bin ke PATH di $SHELL_PROFILE"
      fi
    fi
  fi
fi

echo "[OK] 'p' ($TAG_NAME) berhasil dipasang/diperbarui di: $INSTALL_DIR/p"
echo "[*] Jalankan 'p' di terminal untuk mulai menggunakannya!"
