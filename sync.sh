#!/usr/bin/env bash

TARGET="spandan@192.168.1.15:/home/spandan/Projects/probe/crdt-sql-rs"

echo "=========================================================="
echo "🚀 Initializing Local Mesh Code Sync"
echo "📡 Target: $TARGET"
echo "👀 Watching: ./src, ./assets, Cargo.toml"
echo "=========================================================="

watchexec \
  --clear \
  --restart \
  --exts rs,html,css,js,toml,sql \
  --watch src \
  --watch assets \
  --watch Cargo.toml \
  --watch migrations \
  -- \
  rsync -avz --delete \
  --exclude 'target/' \
  --exclude '.git/' \
  --exclude "'todos_*.db'" \
  --exclude "'todos_*.db-shm'" \
  --exclude "'todos_*.db-wal'" \
  --exclude 'users.db' \
  --exclude 'users.db-shm' \
  --exclude 'users.db-wal' \
  --exclude 'node.key' \
  ./ "$TARGET"
