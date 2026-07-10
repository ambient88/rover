#!/usr/bin/env bash
# rover installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ambient88/rover/main/scripts/install.sh | bash

set -euo pipefail

REPO="ambient88/rover"
BINARY_NAME="rover"
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
echo "Fetching latest rover release..."
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
echo "rover installed: ${INSTALL_DIR}/${BINARY_NAME}"

# ── Download data files now, with progress (rover update) ────────────────────
# Best-effort: if this fails (e.g. offline), the first real run auto-fetches them.
echo ""
echo "Downloading data files..."
if "${INSTALL_DIR}/${BINARY_NAME}" update; then
    echo ""
    echo "Setup complete. Run 'rover' to get started."
else
    echo ""
    echo "Data download did not complete — it will be retried automatically on first run."
    echo "You can also run 'rover update' manually. Run 'rover' to get started."
fi
