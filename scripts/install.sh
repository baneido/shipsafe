#!/bin/sh
# ShipSafe installer.
#
#   curl -sSL https://install.shipsafe.dev | sh
#   curl -sSL https://install.shipsafe.dev | sh -s -- --version v0.1.0
#
# Downloads a prebuilt binary from GitHub Releases for the current OS/arch
# and installs it to --bin-dir (default: /usr/local/bin, falling back to
# ~/.local/bin when not writable).
set -eu

REPO="baneido/shipsafe"
VERSION="latest"
BIN_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --bin-dir)
      BIN_DIR="$2"
      shift 2
      ;;
    --bin-dir=*)
      BIN_DIR="${1#--bin-dir=}"
      shift
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux) os_part="unknown-linux-gnu" ;;
  Darwin) os_part="apple-darwin" ;;
  *)
    echo "shipsafe installer: unsupported OS: $OS (use cargo install shipsafe)" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64 | amd64) arch_part="x86_64" ;;
  arm64 | aarch64) arch_part="aarch64" ;;
  *)
    echo "shipsafe installer: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

TARGET="${arch_part}-${os_part}"
ASSET="shipsafe-${TARGET}.tar.gz"

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  case "$VERSION" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
  esac
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

if [ -z "$BIN_DIR" ]; then
  if [ -w /usr/local/bin ]; then
    BIN_DIR="/usr/local/bin"
  else
    BIN_DIR="${HOME}/.local/bin"
  fi
fi
mkdir -p "$BIN_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${URL} ..."
if ! curl -fsSL "$URL" -o "${TMP_DIR}/${ASSET}"; then
  echo "shipsafe installer: download failed for ${ASSET} (${VERSION})." >&2
  echo "Check available releases at https://github.com/${REPO}/releases" >&2
  exit 1
fi

# Verify checksum when published alongside the asset.
if curl -fsSL "${URL}.sha256" -o "${TMP_DIR}/${ASSET}.sha256" 2>/dev/null; then
  (
    cd "$TMP_DIR"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c "${ASSET}.sha256"
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 -c "${ASSET}.sha256"
    fi
  ) || {
    echo "shipsafe installer: checksum verification failed" >&2
    exit 1
  }
fi

tar -xzf "${TMP_DIR}/${ASSET}" -C "$TMP_DIR"
install -m 755 "${TMP_DIR}/shipsafe" "${BIN_DIR}/shipsafe"

echo "✔ shipsafe installed to ${BIN_DIR}/shipsafe"
"${BIN_DIR}/shipsafe" version || true

case ":$PATH:" in
  *:"$BIN_DIR":*) ;;
  *)
    echo "note: add ${BIN_DIR} to your PATH" >&2
    ;;
esac
