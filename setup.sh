#!/usr/bin/env bash
# Quick start: create config dir, SSH key, and config.yaml from the example.
set -e
cd "$(dirname "$0")"

mkdir -p config

if [ ! -f config/id_ed25519 ]; then
  ssh-keygen -t ed25519 -N "" -C "pc-power-panel" -f config/id_ed25519
  echo "✅ SSH key created at config/id_ed25519"
else
  echo "• SSH key already exists"
fi

if [ ! -f config/config.yaml ]; then
  cp config.example.yaml config/config.yaml
  echo "✅ config/config.yaml created — edit it to add your devices"
else
  echo "• config/config.yaml already exists"
fi

echo
echo "Public key to add to each target's ~/.ssh/authorized_keys:"
echo "------------------------------------------------------------"
cat config/id_ed25519.pub
echo "------------------------------------------------------------"
echo "Next: edit config/config.yaml, then run: docker compose up -d --build"
