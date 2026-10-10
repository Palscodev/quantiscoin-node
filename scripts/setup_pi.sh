#!/usr/bin/env bash
# Install a QuantisCoin node on Raspberry Pi OS / Debian / Ubuntu.
#   bash scripts/setup_pi.sh
set -euo pipefail
cd "$(dirname "$0")/.."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e . --no-deps
echo
echo "Installed. Next:"
echo "  1. Edit config/node.toml (your wallet address and the network's peer address)"
echo "  2. .venv/bin/python -m quantis node --config config/node.toml"
