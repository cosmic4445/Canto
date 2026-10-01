#!/usr/bin/env sh
set -e
cd "$(dirname "$0")/../.."

missing=""
for tool in cargo node npm cc; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
  echo "Missing:$missing"
  echo "Debian/Ubuntu: sudo apt install build-essential curl nodejs npm   (then install Rust from https://rustup.rs)"
  echo "Fedora:        sudo dnf install gcc nodejs npm rust cargo"
  echo "Arch:          sudo pacman -S base-devel nodejs npm rustup && rustup default stable"
  exit 1
fi

(cd apps/desktop && npm install --no-audit --no-fund && npm run build)
cargo build --release -p canto-app
echo "Built: target/release/canto"
