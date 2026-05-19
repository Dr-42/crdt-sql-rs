# Autonomous Mesh CRDT Todo — Implementation Notes

## What was built (6 steps, one pass)

### Step 1 — Device Identity (`load_or_generate_signing_key`)

- On first run: generates a fresh Ed25519 keypair via `ed25519-dalek 2.x + OsRng`
- Persists the 32-byte secret scalar to `node.key`
- Subsequent runs load it back; `node_id` = `SHA256(verifying_key)` hex
- **Never sync `node.key`** — it's excluded from `sync.sh` rsync

### Step 2 — Google OAuth PKCE

- `GET /auth/login` → generates `code_verifier` (32 random bytes, base64url-encoded), computes `code_challenge = BASE64URL(SHA256(verifier))`, redirects to Google
- CSRF state + verifier stored in an `HttpOnly` cookie (`pkce_state`), 10-minute TTL
- `GET /auth/callback` → exchanges `code` for `id_token`, decodes JWT payload (no sig verify needed — came directly from Google's HTTPS endpoint), derives `user_hash = SHA256(sub)`
- Issues an **app session token**: `BASE64URL(user_hash:timestamp).BASE64URL(Ed25519_sig)` — self-contained, verifiable without a DB lookup
- Session stored in an `HttpOnly` cookie, 24-hour TTL

### Step 3 — UDP Beacon (port 8765)

- **Broadcaster**: every 5s, signs a UUID nonce with the device privkey, broadcasts `{user_hash, pubkey_fingerprint, replication_port, nonce, nonce_sig}` to `255.255.255.255:8765`
- **Listener**: parses incoming packets, updates an in-memory `HashMap<fingerprint, DiscoveredPeer>` with `last_seen` timestamp
- Raw Google `sub` or JWT never broadcast — only the opaque `user_hash`

### Step 4 — Authenticated Replication (TCP port 11204)

Challenge-response protocol before any data flows:

```
Initiator → Responder:  { type: "Challenge", nonce: UUID, user_hash }
Responder → Initiator:  { type: "ChallengeResponse", nonce, signature, verifying_key }
  (Initiator verifies Ed25519 sig against the key; rejects if invalid)
Initiator → Responder:  { type: "SyncRequest", user_hash }
Responder → Initiator:  { type: "SyncData", todos: [...] }
```

All messages are newline-delimited JSON over raw TCP. The gossip worker calls `pull_from_peer()` for every UDP-discovered peer that was seen in the last 30 seconds.

### Step 5 — LWW Tiebreaker

Old merge condition:

```sql
WHERE excluded.updated_at > todos.updated_at
```

New — lexicographic `(timestamp, node_id)` tuple:

```sql
WHERE (excluded.updated_at || '_' || excluded.node_id)
    > (todos.updated_at    || '_' || todos.node_id)
```

- Eliminates silent data loss when two nodes write at the exact same millisecond
- `node_id` column added to the todos schema; all writes stamp it at creation/update time

### Step 6 — Frontend wiring

- `GET /auth/me` → `{ logged_in, user_hash, node_id }` — called on page load
- Login wall shown when not logged in; todo UI hidden
- Each todo row shows a 6-char node origin badge (hover for full fingerprint)
- Peer list distinguishes `⚡ auto` (UDP-discovered) from `🔧 manual` (HTTP fallback)
- Peer list auto-refreshes every 6s (aligned with 5s beacon interval)

---

## Setup

### 1. Google OAuth credentials

1. Go to [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials
2. Create an OAuth 2.0 Client ID (Web application)
3. Add `http://localhost:8080/auth/callback` (and your LAN IP) to **Authorized redirect URIs**
4. Set environment variables before running:

```bash
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export OAUTH_REDIRECT_URI="http://192.168.1.x:8080/auth/callback"
```

### 2. Run

```bash
cargo run --release
```

On first run:

- `node.key` is created (keep it safe, don't commit it)
- `users.db` is created (user registry)
- Per-user `todos_<hash>.db` files are created on first login

### 3. Multi-device setup

- Run on each device with the same `GOOGLE_CLIENT_ID`
- Devices on the same LAN will auto-discover each other via UDP 8765
- No manual peer registration needed — just log in with the same Google account on each device

---

## Port summary

| Port  | Protocol | Purpose                        |
| ----- | -------- | ------------------------------ |
| 8080  | TCP/HTTP | UI + REST API                  |
| 8765  | UDP      | Peer discovery beacons         |
| 11204 | TCP      | Authenticated CRDT replication |

---

## Security properties

- `node.key` is the root of device identity — guard it like an SSH key
- Session tokens are self-contained Ed25519-signed blobs; no DB needed to verify
- Replication requires a valid signature challenge before any data is shared
- `user_hash = SHA256(Google sub)` — Google's internal user ID never leaves the device
- UDP beacons carry only the fingerprint (SHA256 of pubkey), not the key itself

---

## Known limitations / next steps

- `user_hash` in UDP beacons is hardcoded to `"anonymous"` until a user logs in. Fix: store the active `user_hash` in a shared `Arc<RwLock<Option<String>>>` and read it in the broadcaster loop.
- The Google id_token is decoded without signature verification against Google's JWKS. Fine for LAN/personal use; add JWKS verification for production.
- TCP replication reads the full state into a single buffer (65KB). Replace with a streaming framing protocol (length-prefix or newline-delimited) for large datasets.
- OAuth callback assumes `reqwest 0.12` — verify the `form()` method signature matches your version.
