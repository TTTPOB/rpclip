#!/bin/bash

# GitHub repository details
REPO="tttpob/rpclip"

# Determine system architecture
ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]; then
    ASSET_NAME="rpclip-client-x86_64-linux-musl"
elif [[ "$ARCH" == "aarch64" ]]; then
    ASSET_NAME="rpclip-client-aarch64-linux-musl"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Get latest release version from GitHub API
LATEST_RELEASE=$(curl -s https://api.github.com/repos/$REPO/releases/latest | jq -r '.tag_name')
echo "Latest version: $LATEST_RELEASE"

# Construct download URL
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/$ASSET_NAME"

# Create temp working dir
TMPDIR=$(mktemp -d)
echo "Using temp directory: $TMPDIR"

# Download binary
curl -L "$DOWNLOAD_URL" -o "$TMPDIR/$ASSET_NAME"
chmod +x "$TMPDIR/$ASSET_NAME"
echo "Downloaded and set executable permissions on $TMPDIR/$ASSET_NAME"

# Determine install path
if [[ "$EUID" -eq 0 ]]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    echo "Created $INSTALL_DIR directory"
fi

# Move binary
mv "$TMPDIR/$ASSET_NAME" "$INSTALL_DIR/rpclip-client"
echo "Moved $ASSET_NAME to $INSTALL_DIR/rpclip-client"

# Create rpc and rpp wrapper scripts
echo '#!/usr/bin/env bash
rpclip-client set' > "$TMPDIR/rpc"
chmod +x "$TMPDIR/rpc"
mv "$TMPDIR/rpc" "$INSTALL_DIR/rpc"
echo "Installed rpc script to $INSTALL_DIR/rpc"

echo '#!/usr/bin/env bash
rpclip-client get' > "$TMPDIR/rpp"
chmod +x "$TMPDIR/rpp"
mv "$TMPDIR/rpp" "$INSTALL_DIR/rpp"
echo "Installed rpp script to $INSTALL_DIR/rpp"

# Clean up temp dir
rm -rf "$TMPDIR"
