#!/usr/bin/env bash
# Sync Mac dev tree → Ubuntu lab VM (IntelliShield).
# Usage: ./scripts/sync_to_vm.sh [VM_USER@VM_HOST]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-akshay@192.168.64.5}"
REMOTE_DIR="${REMOTE_DIR:-intellishield-sdn}"

echo "Sync: $ROOT → ${TARGET}:~/${REMOTE_DIR}/"
rsync -avz --delete \
  --exclude '.git/' \
  --exclude '.venv/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  --exclude 'node_modules/' \
  "$ROOT/" "${TARGET}:~/${REMOTE_DIR}/"

echo "OK: sync complete."
