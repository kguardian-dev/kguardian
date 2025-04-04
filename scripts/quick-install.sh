#!/bin/bash

echo "Starting the installation of kubectl-advisor..."

# Define the GitHub owner and repository
GITHUB_OWNER="xentra-ai"
GITHUB_REPO="kube-guardian"
BINARY_NAME="xentra"
INSTALL_DIR="/usr/local/bin"
TMP_DIR=$(mktemp -d)
BINARY_PATH="$TMP_DIR/$BINARY_NAME"

# Trap to ensure that the temporary directory gets cleaned up
cleanup() {
    echo "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Detect OS and Arch
echo "Detecting OS and architecture..."
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

echo "Detected OS: $OS, Arch: $ARCH"

# Get the latest release tag
echo "Fetching the latest release tag..."
LATEST_RELEASE_TAG=$(curl -s "https://api.github.com/repos/$GITHUB_OWNER/$GITHUB_REPO/releases/latest" | grep tag_name | cut -d '"' -f 4)

# Check if the latest release was found
if [ -z "$LATEST_RELEASE_TAG" ]; then
    echo "Error: Failed to fetch the latest release."
    exit 1
fi

echo "Latest release tag: $LATEST_RELEASE_TAG"

# Construct the download URL
BINARY_URL="https://github.com/$GITHUB_OWNER/$GITHUB_REPO/releases/download/$LATEST_RELEASE_TAG/$BINARY_NAME-$OS-$ARCH"
echo "Download URL: $BINARY_URL"

# Download the release and set it as executable
echo "Downloading the kubectl-advisor binary..."
curl -sL "$BINARY_URL" -o "$BINARY_PATH"
if [ $? -ne 0 ]; then
    echo "Error: Failed to download the binary."
    exit 1
fi

chmod +x "$BINARY_PATH"

# Notify user about the need for elevated permissions
echo "The kubectl-advisor binary needs to be moved to $INSTALL_DIR, which requires elevated permissions."
echo "You may need to provide your password for sudo access."

# Move the binary to /usr/local/bin and rename it
sudo mv "$BINARY_PATH" "$INSTALL_DIR/kubectl-$BINARY_NAME"

echo "Installation successful! 'kubectl-$BINARY_NAME' is now available in your PATH."
echo "You can start using it with 'kubectl xentra'."

# Cleanup is handled by the trap, but you can call it explicitly if desired
cleanup
