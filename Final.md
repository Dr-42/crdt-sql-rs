# Final Architecture

## Revised Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    STARTUP SEQUENCE                      │
│                                                          │
│  1. Load or generate Ed25519 keypair → node.key         │
│  2. OAuth login → get `sub` from Google JWT             │
│  3. POST /auth/register {sub, pubkey} → get app_token   │
│  4. Open todos_{user_hash}.db                           │
│  5. Spawn UDP beacon (8765) + HTTP server (8080/11204)  │
└─────────────────────────────────────────────────────────┘

┌───────────────────────┐     UDP 8765      ┌─────────────────────┐
│      Device A         │ ←── beacon ────── │     Device B        │
│  user: alice          │                   │  user: alice        │
│  pubkey: 0xABCD       │ ──► beacon ──────►│  pubkey: 0xEF01     │
└───────────┬───────────┘                   └──────────┬──────────┘
            │                                          │
            │         TCP 11204 (replication)          │
            │   1. A→B: "sync request" + nonce         │
            │   2. B→A: nonce signed by privkey        │
            │   3. A verifies sig against known pubkey │
            │   4. Full CRDT exchange                  │
            └──────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    DB LAYOUT                             │
│                                                          │
│  users.db          → {user_hash, pubkey, last_seen}     │
│  todos_<hash>.db   → per-user CRDT todo store           │
│  node.key          → this device's Ed25519 keypair      │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation Order

1. **Device identity** — generate/load `node.key` (Ed25519, use the `ed25519-dalek` crate)
2. **Auth flow** — Google OAuth PKCE in the browser, backend exchanges for app token, stores `{user_hash → pubkeys}` in `users.db`
3. **Per-user DB** — open `todos_{user_hash}.db` after login, pass it as state scoped to that session
4. **UDP beacon** — broadcast `{pubkey_fingerprint, port, signed_nonce}` on 8765 every 5s; listen and build a peer table
5. **Authenticated replication** — challenge-response on 11204 before any CRDT exchange
6. **LWW tiebreaker fix** — `(updated_at, node_id)` in the merge query

---

## Crates you'll need to add

```toml
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
sha2 = "0.10"
jsonwebtoken = "9"          # for verifying Google JWTs
oauth2 = "4"                # PKCE flow
tokio = { ..., features = ["net"] }  # already have, UDP via UdpSocket
```

---

The two-port split (8080 UI, 11204 replication) is clean and I'd keep it. The DB-per-user approach is the right call — avoids any cross-contamination and makes backup/wipe trivial.

Want me to start with the device identity + UDP discovery layer, or the OAuth flow first? The auth piece gates everything else, so that's probably the right starting point.
