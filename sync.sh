#!/usr/bin/env bash

# Define your target node here
TARGET="spandan@192.168.1.15:/home/spandan/Projects/probe/crdt-sql-rs"

echo "=========================================================="
echo "🚀 Initializing Local Mesh Code Sync"
echo "📡 Target: $TARGET"
echo "👀 Watching: ./src, ./assets, Cargo.toml"
echo "=========================================================="

# Run watchexec
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
  --exclude 'todos.db' \
  --exclude 'todos.db-shm' \
  --exclude 'todos.db-wal' \
  --exclude 'node.key' \
  ./ "$TARGET"
