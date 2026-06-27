#!/usr/bin/env bash
# SubnetSearch installer
# Usage: curl -fsSL https://raw.githubusercontent.com/greshnik200ready2die/SubnetSearch/main/scripts/install.sh | bash

set -euo pipefail

REPO="greshnik200ready2die/SubnetSearch"
BINARY_NAME="subnetSearch"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ── Detect OS and architecture ────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)          ARCH="x64"   ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
esac

case "$OS" in
    linux)  ASSET="${BINARY_NAME}-linux-${ARCH}" ;;
    darwin) ASSET="${BINARY_NAME}-osx-${ARCH}"   ;;
    *)      echo "Unsupported OS: $OS. Download manually from https://github.com/${REPO}/releases" && exit 1 ;;
esac

# ── Fetch latest release download URL ────────────────────────────────────────
echo "Fetching latest SubnetSearch release..."
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
DOWNLOAD_URL=$(curl -fsSL "$API_URL" \
    | grep "browser_download_url" \
    | grep "${ASSET}" \
    | head -1 \
    | cut -d'"' -f4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Could not find a release binary for ${OS}/${ARCH}."
    echo "Please download manually from https://github.com/${REPO}/releases"
    exit 1
fi

# ── Download and install ──────────────────────────────────────────────────────
TMP=$(mktemp)
echo "Downloading ${ASSET}..."
curl -fsSL "$DOWNLOAD_URL" -o "$TMP"

# Require sudo only if INSTALL_DIR is not writable
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TMP" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo ""
echo "SubnetSearch installed: ${INSTALL_DIR}/${BINARY_NAME}"
echo "Run 'subnetSearch' to get started. Data files are downloaded on first run."
