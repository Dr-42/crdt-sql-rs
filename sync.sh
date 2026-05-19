#!/usr/bin/env bash

#TARGET="spandan@192.168.1.15:/home/spandan/Projects/probe/crdt-sql-rs"
TARGET="u_0a355@192.168.1.8:/data/data/com.termux/files/home/crdt-sql-rs"

# Exporting this bypasses the need for the -e flag entirely,
# preventing watchexec from breaking our string.
export RSYNC_RSH="ssh -p 8022"

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
  --exclude 'todos_*.db' \
  --exclude 'users.db' \
  --exclude 'node.key' \
  ./ "$TARGET"
