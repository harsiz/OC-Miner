# OmegaCases Mining & Mining Pools — Reference for Agents/LLMs

Audience: an LLM or autonomous agent that needs to (a) write a solo miner, (b) write a
mining pool server, or (c) reason about/modify OmegaCases's mining backend. This is a
dense technical reference, not a tutorial — it states exact contracts, exact math, and
exact edge-case behavior as implemented in this codebase, with file:line pointers so you
can go read the authoritative source instead of trusting prose.

There is also a human-facing version of part of this (registration flow, "why", prose)
rendered in-app at `/developer/docs/mining-pools`, sourced from
`app/developer/docs/[section]/page.tsx` (`MiningPoolsDocs()`, ~line 564). This document
supersedes it in detail and also covers solo mining, the data model, and internals that
page doesn't mention.

---

## 1. Mental model

OmegaCases runs a single global, server-authoritative proof-of-work chain. There is one
canonical `height`, one canonical `target` (difficulty), and one linear sequence of
`mining_blocks` rows, each pointing at the previous block's hash. There is no P2P
network and no client-side chain validation — the OmegaCases server is the sole
arbiter of validity, ordering, and reward. "Mining" here means: repeatedly try nonces
until `SHA256(preimage)` is numerically less than the current target, then race to be
the first to POST that winning nonce to the server before someone else claims the same
height.

Two ways to participate:

- **Solo mining**: you supply your own `user_id` as the miner identity and submit
  directly to `POST /api/mining`. You keep 100% of the block reward.
- **Pool mining**: a pool operator runs a server that miners point their hashpower at.
  The pool tracks shares internally (however it wants) and, when it finds a block,
  calls `POST /api/mining/pools/{id}/submit-block` with the shares to split the reward
  across whichever of its members it says are ontributors. OmegaCases is not involved in
  actually distributing hashpower to a pool — it only (1) publicly lists pools, (2)
  periodically checks a pool is alive via TCP, (3) lets users declare pool membership,
  and (4) does the reward-splitting math and balance crediting when told a block was
  found.

Everything below is implemented in:
- `lib/mining.ts` — PoW math, difficulty retarget, halving schedule, atomic block-claim RPC wrapper
- `lib/pool-auth.ts` — pool API key generation/hashing/verification
- `app/api/mining/route.ts` — solo mining GET/POST
- `app/api/mining/verify/route.ts` — hash-debugging helper
- `app/api/mining/blocks/route.ts` — block feed (list + single lookup, with pool shares)
- `app/api/mining/pools/route.ts` — pool list + register
- `app/api/mining/pools/[id]/route.ts` — pool detail/edit/delete
- `app/api/mining/pools/[id]/join/route.ts` — membership
- `app/api/mining/pools/[id]/submit-block/route.ts` — pool block submission + payout split
- `netlify/functions/pool-liveness-test-background.ts` — initial 30s liveness check
- `netlify/functions/pool-uptime-sweep.ts` — recurring 5-minute uptime check
- `scripts/002_zites_and_pools.sql` — full schema (source of truth for column types/constraints)

`BASE` below means the site origin, e.g. `https://omegacases.example` — endpoints are
relative to it.

---

## 2. Proof-of-work algorithm (exact)

### 2.1 Preimage

```
preimage = previous_hash + id_no_dashes + nonce
```

- `previous_hash`: the `hash` field of the block at `height - 1` (lowercase hex string,
  no `0x` prefix). For the genesis block (`height == 0`) it is the literal string
  `"0000000000000000000000000000000000000000000000000000000000000000"` (68 zero
  chars — this is intentionally longer than a normal 64-hex-char hash; it is just a
  placeholder constant, do not "fix" its length).
- `id_no_dashes`: **solo mining** → your `user_id` UUID with all `-` characters
  stripped (`id.replace(/-/g, "")`). **Pool mining** → the pool's own `id` UUID, same
  dash-stripping, used *instead of* any individual miner's id, because a pool block has
  no single miner.
- `nonce`: coerced with `Number(nonce)` server-side, then interpolated as a plain
  decimal integer string (no leading zeros, no separators, no hex). Send it as either a
  JSON number or a numeric string — both work, but avoid non-integer values.

All three parts are simply string-concatenated, no delimiter. Exact code
(`lib/mining.ts:104-107`):

```ts
export function buildPreimage(previousHash: string, minerOrPoolId: string, nonce: number | string): string {
  const idNoDashes = minerOrPoolId.replace(/-/g, "")
  return `${previousHash}${idNoDashes}${nonce}`
}
```

### 2.2 Hash

```
hash = SHA256(preimage), output as lowercase hex
```

Node: `createHash("sha256").update(preimage).digest("hex")`.

### 2.3 Validity check

A hash is valid iff, interpreted as a big integer, it is **strictly less than** the
current 64-hex-char `target` (also interpreted as a big integer). Equal is *not* valid.

```ts
const hashInt = BigInt("0x" + hash)
const targetInt = BigInt("0x" + target)
hashInt < targetInt  // valid
```

The server recomputes the hash itself from `previous_hash + id_no_dashes + nonce` and
compares it to what you submitted — if your submitted `hash` doesn't match the
server-computed one, you get `400 { error: "Hash verification failed" }` with a `debug`
object containing the exact preimage and server-computed hash it used, so you can diff
against your own implementation. **Use this to debug your miner, not just to log an
error** — the `debug.note` field literally spells out the preimage recipe.

### 2.4 Debugging endpoint

`GET /api/mining/verify?prev_hash=...&miner_id=...&nonce=...` (`app/api/mining/verify/route.ts`)
returns exactly what the server would compute for a given input, with no side effects
(no auth, no submission, pure function). Use this while developing a miner/pool to
confirm your local hash implementation matches the server's byte-for-byte before you
start real proof-of-work search. Note the query param is `miner_id` even when
debugging a *pool* preimage — just pass the pool's id there, the endpoint doesn't care
what kind of id it is, it only strips dashes and concatenates.

```
GET /api/mining/verify?prev_hash=0000...0000&miner_id=<uuid>&nonce=12345
→ { preimage, preimage_length, hash, note }
```

### 2.5 Target format

- Always a 64-character lowercase hex string (256-bit number space).
- Normalization (`normalizeTarget`, `lib/mining.ts:27-30`): non-hex chars stripped,
  right-padded with `f` to 64 chars if short, truncated from the right if long. You
  should never need to normalize a target yourself — always use the exact `target`
  string returned by `GET /api/mining`, unmodified, in your validity pre-check before
  submitting.
- Default/genesis target: `00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`
  (~16 leading hex zeros' worth of difficulty budget with the rest `f`).

---

## 3. Solo mining

### 3.1 `GET /api/mining` — read current chain state

No auth. Poll this before starting a search and again any time you get a `409`
(someone else claimed the height first), since target/height/previous_hash all change
on every new block.

```json
{
  "target": "000000abcdef...64 hex chars",
  "height": 1234,
  "previous_hash": "000000...64 hex chars (or genesis placeholder at height 0)",
  "reward_zites": 64,
  "zites_halving": {
    "next_height": 1400,
    "blocks_remaining": 166,
    "eta_ms": 59760000
  },
  "difficulty_adjustment": {
    "next_height": 1240,
    "blocks_remaining": 6
  }
}
```

### 3.2 `POST /api/mining` — submit a solo-found block

No pool auth needed — solo mining is tied to a normal `user_id`, not an API key. There
is currently **no signature/session check** on this endpoint beyond the `miner_id`
needing to exist as a real user row — anyone who knows a valid `user_id` and finds a
real PoW solution can credit that user's balance. This is by design (mining rewards are
meant to be earned by computation, not gated behind auth), but it means `miner_id` must
be a real user's UUID (looked up against `users` table; 404 if not found).

Request:
```json
{ "miner_id": "uuid", "nonce": 918234, "hash": "0000abc...64 hex chars" }
```

Success (200):
```json
{
  "success": true,
  "block": { "height": 1234, "hash": "0000abc...", "reward_zites": 64, "miner": "username" },
  "next": { "height": 1235, "target": "000000...64 hex chars" }
}
```

Error cases:
| Status | Body | Meaning |
|---|---|---|
| 400 | `{ error: "miner_id, nonce, and hash are required" }` | missing field |
| 404 | `{ error: "Miner not found" }` | `miner_id` doesn't match a `users` row |
| 400 | `{ error: "Hash verification failed", debug: {...} }` | your hash ≠ server-recomputed hash for that preimage |
| 400 | `{ error: "Hash does not meet target difficulty" }` | hash is valid SHA256 of the preimage but ≥ target |
| 409 | `{ error: "Block already claimed — a faster miner beat you to it" }` | height race lost — **re-fetch `GET /api/mining` and keep mining at the new height/target**, do not retry the same submission |

On success the server, in one atomic sequence:
1. Locks and advances `mining_height` and inserts the `mining_blocks` row via the
   `claim_mining_block` Postgres RPC (`lib/mining.ts:71-97`) — this is what makes height
   races resolve into a clean win/lose instead of a corrupted chain.
2. Credits `reward_zites` to the miner's `zites_balance` via the `credit_zites_balance`
   RPC (atomic increment, no read-modify-write race).
3. Runs the difficulty retarget if this new height lands on a retarget boundary (see §5).

---

## 4. Reward schedule (halving)

```
reward_zites(height) = 128 / 2^floor(height / 200)
```
(`ZITES_REWARD_GENESIS = 128`, `ZITES_HALVING_INTERVAL = 200`, `lib/mining.ts:4-10`)

Block 0–199 pay 128 Zites, blocks 200–399 pay 64, 400–599 pay 32, etc. `zites_halving`
in the `GET /api/mining` response tells you the next halving height, blocks remaining,
and an ETA in ms computed as `blocks_remaining * TARGET_BLOCK_TIME_MS` — this ETA is a
naive linear projection at the target block time, not based on actual recent block
timing, so treat it as a rough estimate.

---

## 5. Difficulty retarget (exact)

Runs automatically, server-side, whenever a newly-claimed block's height is a multiple
of `DIFFICULTY_ADJUSTMENT_INTERVAL = 10`. You never call this yourself; it's a
side-effect of `POST /api/mining` and `POST /api/mining/pools/{id}/submit-block`.
(`maybeRetargetDifficulty`, `lib/mining.ts:150-192`)

Algorithm (same shape as Bitcoin's retarget):
1. Take the `found_at` timestamps of the last 10 blocks.
2. `actualMs = newest.found_at - oldest.found_at`
3. `expectedMs = 9 * TARGET_BLOCK_TIME_MS` (9, not 10 — it's the span between the
   oldest and newest of 10 samples, i.e. 9 intervals)
4. `factor = clamp(actualMs / expectedMs, 0.5, 3.0)`
5. `new_target = current_target * factor` (as BigInt fixed-point math, scaled by 1e6
   then divided back down), clamped into
   `[0x0000000000000001000000000000000000000000000000000000000000000000, 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]`.

Interpretation: blocks came in **faster** than 6 min average → `actualMs < expectedMs`
→ `factor < 1` → target shrinks → next 10 blocks are **harder**. Blocks came in
**slower** → target grows → **easier**. Single retarget step is capped to at most 3x
easier or 2x harder (0.5–3.0 factor range) per 10-block window, so difficulty cannot
swing arbitrarily far in one step.

Concurrency: the retarget itself goes through an `apply_difficulty_retarget` RPC keyed
on the adjustment height, so if two blocks somehow land on the same retarget boundary
concurrently, only the first application sticks and the second call is a no-op that
just returns the already-applied target — you can't double-apply the factor by racing.

`TARGET_BLOCK_TIME_MS = 6 * 60 * 1000` (6 minutes) is the constant the whole system is
tuned around.

---

## 6. Building your own solo miner (what's actually required)

1. `GET /api/mining` → `{ target, height, previous_hash }`.
2. Loop: pick a `nonce`, compute `preimage = previous_hash + your_user_id_no_dashes + nonce`,
   `hash = sha256hex(preimage)`, check `BigInt("0x"+hash) < BigInt("0x"+target)`.
3. On a hit, `POST /api/mining` with `{ miner_id, nonce, hash }`.
4. On `409` (lost the race) or any successful submission by anyone (you can watch for
   this via Supabase Realtime, see §10), re-fetch `GET /api/mining` for the new
   height/target/previous_hash and resume searching.
5. Nonce space/type: send it as a JSON number if it fits safely in a JS/IEEE754 double
   (i.e. below 2^53); the server does `Number(nonce)` on it either way. There's no
   documented upper bound enforced by the server beyond that.

There is an existing reference miner at `github.com/harsiz/oc-miner` (external repo,
not part of this codebase) that already implements this and supports pointing at a
pool. If you're asked to "build a miner," check whether extending/using that is more
appropriate than writing one from scratch — this repo doesn't contain its source, so
don't assume internal implementation details about it beyond what's stated here and in
the in-app docs.

---

## 7. Mining pools

### 7.1 What a pool operator must build

Only two hard requirements, everything else (listing, uptime checks, membership,
reward-split accounting, balance crediting) is handled by OmegaCases:

1. **A TCP listener on the host:port you register that answers `PING` with `PONG`.**
   This is the entire liveness contract — see §7.4. Nothing else about your wire
   protocol to actual miners is dictated by OmegaCases.
2. **Your own logic for accepting miner connections, tracking shares however you like
   (PPLNS/PPS/proportional/whatever), and calling `submit-block` when your pool finds a
   valid block.**

OmegaCases does not define or require any particular protocol between your pool server
and the individual miners connecting to it — that's entirely internal to your pool.
The only OmegaCases-facing contracts are: the raw-TCP PING/PONG liveness port, and the
HTTP `submit-block` call. (A reference implementation, `oc-pool-server`, ships with
`github.com/harsiz/oc-miner` and implements a documented newline-delimited-JSON
protocol between itself and the miner binary — but that miner↔pool wire protocol is
external to this repo and not required; you can implement any protocol you want between
your pool and your own miners.)

### 7.2 Registering a pool — `POST /api/mining/pools`

No pool-API-key auth yet (you don't have one). Normal user context — `owner_id` must be
a real user id.

Request:
```json
{
  "owner_id": "your-user-uuid",
  "name": "My Pool",
  "host": "203.0.113.10",
  "port": 3333,
  "ip_version": "auto",
  "description": "optional, PPLNS, low fee, etc"
}
```

Validation (`app/api/mining/pools/route.ts:36-59`):
- `owner_id`, `name`, `host`, `port` required.
- `host` must match `/^[a-zA-Z0-9.:\-]+$/` (hostnames, IPv4, and IPv6 literals with
  colons are all fine; no protocol prefix, no path).
- `port` in `[1, 65535]`.
- `ip_version` ∈ `{ipv4, ipv6, auto}`, defaults to `auto`.
- `owner_id` must resolve to an existing `users` row (404 otherwise).

Response (200):
```json
{
  "success": true,
  "pool": { "id": "pool-uuid", "status": "testing", "...": "rest of the mining_pools row minus api_key_hash" },
  "api_key": "64-char hex, shown ONLY here",
  "warning": "Save this API key now, it will not be shown again."
}
```

**The plaintext `api_key` is returned exactly once, in this response, and never again.**
The server only ever stores `sha256(api_key)` (`api_key_hash` column) plus an 8-char
`api_key_prefix` for display purposes (`lib/pool-auth.ts`). If it's lost, there is no
recovery endpoint in this codebase — you'd need to re-register a new pool (or ask
whoever has DB access to manually rotate `api_key_hash`, but no API does this).

If `POOL_LIVENESS_FUNCTION_URL` is configured server-side, registration immediately
fires-and-forgets a liveness test trigger and flips status to `testing`; if that env
var isn't set (e.g. local dev), the pool just sits at `pending` until something else
triggers a check (editing host/port re-triggers it too, see §7.6).

### 7.3 Pool lifecycle / `status` values

```
pending → testing → active ⇄ offline
              ↓
           pending (failed check)
   (also: banned, set manually/administratively — not reachable via any documented API in this codebase)
```

- `pending`: registered but no liveness test has run/passed yet.
- `testing`: liveness test in progress.
- `active`: passed liveness, publicly listed on `/mining` (`GET /api/mining/pools` with
  no filters only returns `status = 'active'` pools).
- `offline`: was active, stopped responding to the recurring uptime sweep.
- `banned`: exists in the schema/type enum but no route here can set it — treat it as
  administrative-only.

**Only `active` pools can call `submit-block` successfully** — the endpoint 403s
otherwise (`pool.status !== "active"`).

### 7.4 Liveness check (initial, ~30s)

`netlify/functions/pool-liveness-test-background.ts`. Triggered right after
registration or a host/port edit. For 30 seconds (`TEST_DURATION_MS`), roughly every
2.5s (`ATTEMPT_INTERVAL_MS`), the server:
1. Opens a raw TCP socket to your registered `host:port` (4s connect timeout).
2. Writes the literal bytes `PING\n`.
3. Waits for any `data` event; checks `data.toString().trim().toUpperCase().includes("PONG")`.
4. Logs each attempt's `ok`/`latency_ms` to `mining_pool_heartbeats`.

Pass condition: `successes / attempts >= 10/12` (`REQUIRED_SUCCESS_RATIO`), i.e. you
need to reliably answer, not just once. On pass: `status → active`,
`last_heartbeat_at` set, and a `pool_activated` notification goes to the owner. On
fail: `status → pending` and a `pool_liveness_failed` notification goes to the owner.

**Implementation requirement for your listener**: accept a plain TCP connection (not
HTTP, not TLS), read at least the 5 bytes `PING\n`, and write back something whose
uppercased, trimmed form contains `PONG` (e.g. just `PONG\n` is simplest and sufficient
— `.includes("PONG")` means extra text around it is fine, but don't overthink it, just
reply with `PONG\n`). Do this quickly (sub-4s) and reliably (this repeats ~12 times
over 30s and you need ~10 of them to succeed).

### 7.5 Ongoing uptime sweep (every 5 minutes)

`netlify/functions/pool-uptime-sweep.ts`, a Netlify **scheduled** function
(`schedule("*/5 * * * *", sweep)`) — runs independently of any pool action, checks
every currently-`active` pool the same PING/PONG way (single attempt per sweep per
pool, not the 12-attempt burst). Each check:
1. Logs a `mining_pool_heartbeats` row.
2. Recomputes `uptime_pct_24h` and `uptime_pct_7d` as `100 * ok_count / total_count`
   over heartbeats in that trailing window (rounded to 2 decimals).
3. If the check failed **and** the pool's last 3 heartbeats (in DB order, not just this
   sweep) are *all* failures, flips `status → offline` and sends a `pool_offline`
   notification to the owner. One isolated failure does not take you offline; three
   consecutive do.

There is no automatic recovery path coded here from `offline` back to `active` — based
on the routes in this repo, the only way back to `active` is the owner re-triggering a
liveness pass, which currently only happens via a `PATCH` that changes `host` or `port`
(see §7.6). If your pool goes `offline` and you fix the underlying issue without
changing host/port, there's no endpoint in this codebase that re-arms the check —
flag this as a gap if asked to improve the system, don't assume a self-heal path
exists.

### 7.6 Editing a pool — `PATCH /api/mining/pools/{id}`

Owner-only (`body.user_id` must equal `pool.owner_id`, else 403). Body: any subset of
`{ user_id, name, host, port, description }`. Changing `host` and/or `port` sets
`status → testing` and re-fires the liveness trigger (same background function as
initial registration) if `POOL_LIVENESS_FUNCTION_URL` is set. Changing only `name`/
`description` does not touch status or re-test anything.

### 7.7 Deleting a pool — `DELETE /api/mining/pools/{id}`

Owner-only. `user_id` accepted from JSON body or `?user_id=` query param. Hard-deletes
the `mining_pools` row; `mining_blocks.pool_id` on any blocks that pool found is set to
`NULL` (FK is `ON DELETE SET NULL`), so historical blocks survive pool deletion but
lose their pool attribution. `mining_pool_members` and `mining_pool_shares` rows
cascade-delete (`ON DELETE CASCADE`).

### 7.8 Listing pools — `GET /api/mining/pools`

No auth. Three modes via query params:
- (no params): only `status = 'active'` pools, newest first. This is what `/mining`'s
  public list uses.
- `?owner_id=<uuid>`: all pools (any status) owned by that user.
- `?mine=1&user_id=<uuid>`: all pools that user is a *member* of (any status), via a
  `mining_pool_members` lookup. Returns `{ pools: [] }` immediately if they're in zero
  pools (skips the second query).

Every mode returns the same row shape, including a joined `owner: { id, username }` and
the public/safe pool fields (never `api_key_hash`).

### 7.9 Pool detail — `GET /api/mining/pools/{id}`

No auth, any status (not filtered to active — you can look up a pending/offline/banned
pool by id directly). Returns `{ pool, recent_blocks }` where `recent_blocks` is the
last 20 blocks that pool found (`height, hash, reward_zites, found_at` only — no miner
identity, this list never included it).

### 7.10 Joining / leaving — `POST` / `DELETE /api/mining/pools/{id}/join`

Body: `{ user_id }`. This **only records site-side membership** — it does not connect
anything, does not tell your pool server anything, and does not require your pool to be
`active`/reachable at all (you can join a `pending` pool). It exists purely so:
(a) the UI can show "you're a member," and (b) `submit-block` can validate that a
`user_id` you're crediting shares to has actually opted in through the site.

Joining response includes `connect: { host, port }` echoing the pool's registered
address — this is informational only, for the user to go type into their own miner
config; nothing is opened server-side. Duplicate join → `409 { error: "Already joined" }`
(unique constraint on `(pool_id, user_id)`).

**A user must separately configure their own mining software with your pool's actual
host/port to contribute hashpower.** Joining on the OmegaCases site is a bookkeeping
step only, not a hashpower-routing step.

### 7.11 Submitting a found block — `POST /api/mining/pools/{id}/submit-block`

**This is the only pool endpoint that requires the pool API key**, sent as
`Authorization: Bearer <api_key>`. Verified by hashing the presented key and comparing
to the stored `api_key_hash` (`authenticatePool`, `lib/pool-auth.ts:20-31`) —
constant-effort lookup, not constant-time compare, so don't rely on this being
timing-attack-hardened; treat the key as a secret regardless. 401 if missing/wrong. 403
if pool `status !== "active"`.

Request:
```json
{
  "nonce": 918234,
  "hash": "0000abc...64 hex chars",
  "shares": [
    { "user_id": "uuid-a", "shares": 1500 },
    { "user_id": "uuid-b", "shares": 800 }
  ]
}
```
`shares` must be a non-empty array; each entry needs a `user_id` and a non-negative
number `shares` (400 otherwise).

Preimage for pool blocks uses the **pool's own id**, not any miner's id — see §2.1.
This is the one place pool submission differs from solo mining's hash construction.

Processing order (`app/api/mining/pools/[id]/submit-block/route.ts`):
1. Auth + status check.
2. Fetch current `target`/`height`, recompute `previous_hash`.
3. Verify PoW exactly like solo mining, but with `minerOrPoolId = poolId`.
4. **Filter `shares` down to only entries whose `user_id` is an existing
   `mining_pool_members` row for this pool.** Anyone not a declared member is silently
   dropped from the payout — not an error by itself. If *zero* entries survive this
   filter, that *is* a 400: `{ error: "None of the reported user_ids have joined this pool" }`.
5. Atomically claim the block (same `claim_mining_block` RPC as solo — same 409
   collision behavior if you lose a height race against another submitter, including
   theoretically another pool or a solo miner).
6. Split `reward_zites` proportionally across the *filtered* shares:
   `zites_credited[i] = reward * (shares[i] / total_shares)`, each rounded to 4 decimal
   places — **except the last participant in submission order, who instead receives
   `reward - sum(everyone_else's_credited_amount)`**, so the total always reconciles to
   exactly the block reward regardless of independent per-entry rounding error. This
   means payout order in your `shares` array has a (tiny, sub-0.0001) financial effect —
   don't rely on any particular participant always being "last" for a reason, it's
   purely a rounding-remainder sink.
7. Each surviving share gets: `credit_zites_balance` RPC call (atomic), a
   `mining_pool_shares` audit row (`block_id, pool_id, user_id, shares, zites_credited`),
   and (as of this feature) **its own `pool_reward` notification** — see §9.
8. Pool row updated: `blocks_found += 1`, `total_shares_reported += totalShares` (using
   the *filtered* total, not the raw submitted total).
9. Owner gets a separate `pool_block_found` notification (pool-level summary, sent
   regardless of whether the owner personally has a share — this is in addition to,
   not instead of, their own `pool_reward` notification if they're also a payout
   recipient).
10. Difficulty retarget check (§5) runs identically to solo mining.

Response (200):
```json
{
  "success": true,
  "block": { "height": 1234, "reward_zites": 64 },
  "payouts": [
    { "user_id": "uuid-a", "shares": 1500, "zites_credited": 41.7391 },
    { "user_id": "uuid-b", "shares": 800,  "zites_credited": 22.2609 }
  ],
  "next": { "height": 1235, "target": "..." }
}
```

Error cases:
| Status | Body | Meaning |
|---|---|---|
| 401 | `{ error: "Invalid or missing pool API key" }` | bad/missing bearer token |
| 403 | `{ error: "Pool is not active" }` | status isn't `active` |
| 400 | `{ error: "nonce, hash, and a non-empty shares array are required" }` | malformed body |
| 400 | `{ error: "Every share entry needs a user_id and a non-negative shares number" }` | bad share entry |
| 400 | `{ error: "None of the reported user_ids have joined this pool" }` | every listed user_id failed the membership filter |
| 400 | `{ error: "Hash verification failed", debug }` / `{ error: "Hash does not meet target difficulty" }` | same PoW failures as solo |
| 409 | `{ error: "Block already claimed — a faster miner beat you to it" }` | height race lost |

**PPLNS/PPS/proportional/whatever share-weighting scheme is entirely your pool's own
business.** OmegaCases takes whatever `shares` numbers you hand it at block-found time
and splits *that block's* reward proportionally among them — it has no concept of
historical share windows, minimum payout thresholds, or fairness across multiple
blocks. All of that internal accounting is your responsibility to track between
submissions.

---

## 8. Data model reference

(Column types/constraints from `scripts/002_zites_and_pools.sql` — treat this as
authoritative over any inferred TypeScript type.)

### `mining_pools`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| owner_id | UUID FK→users, cascade delete | |
| name, host | TEXT NOT NULL | |
| port | INTEGER, CHECK 1–65535 | |
| ip_version | TEXT, CHECK ipv4/ipv6/auto | default `auto` |
| description | TEXT nullable | |
| status | TEXT, CHECK pending/testing/active/offline/banned | default `pending` |
| api_key_hash | TEXT NOT NULL | sha256 of the plaintext key, never exposed |
| api_key_prefix | TEXT NOT NULL | first 8 chars of plaintext key, safe to display |
| last_heartbeat_at | TIMESTAMPTZ nullable | |
| uptime_pct_24h, uptime_pct_7d | NUMERIC(5,2) | default 0 |
| total_shares_reported | BIGINT NOT NULL default 0 | sum of filtered shares ever submitted |
| blocks_found | INTEGER NOT NULL default 0 | |
| member_count | INTEGER NOT NULL default 0 | denormalized, recomputed on join/leave |
| banned_reason | TEXT nullable | |
| created_at, updated_at | TIMESTAMPTZ | |

### `mining_pool_members`
`id, pool_id (FK cascade), user_id (FK cascade), joined_at`. `UNIQUE (pool_id, user_id)`.

### `mining_pool_heartbeats`
`id, pool_id (FK cascade), ok BOOLEAN, latency_ms INTEGER nullable, created_at`.
Append-only liveness log; source of truth for uptime % computation (windowed queries,
no separate rollup table).

### `mining_blocks`
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| height | INTEGER UNIQUE NOT NULL | the canonical chain position |
| hash | TEXT NOT NULL | lowercase hex, stored via `.toLowerCase()` on insert |
| nonce | BIGINT NOT NULL | |
| miner_id | UUID FK→users, cascade delete, **NOT NULL** | for pool blocks this is set to `pool.owner_id` — see §9 UI note, this is *not* who actually contributed hashpower |
| previous_hash | TEXT NOT NULL | |
| target | TEXT NOT NULL | the target that was active when this block was found |
| reward_zites | NUMERIC(18,4) NOT NULL | |
| pool_id | UUID FK→mining_pools, **ON DELETE SET NULL**, nullable | NULL = solo block |
| found_at | TIMESTAMPTZ default now() | |

`miner_id` is always non-null even for pool blocks (it's a NOT NULL column, satisfied by
using the pool owner's id as a placeholder FK target) — **do not use `miner_id` to infer
who mined a pool block**, it identifies the pool's owner account for referential-integrity
purposes only, not an actual contributor. Use `pool_id` + `mining_pool_shares` for real
attribution.

### `mining_pool_shares` (audit trail, pool blocks only)
`id, block_id (FK→mining_blocks cascade), pool_id (FK cascade), user_id (FK cascade),
shares BIGINT CHECK >=0, zites_credited NUMERIC(18,4), created_at`. One row per
surviving (post-membership-filter) share entry per submit-block call.

### `game_settings` (key/value, internal chain state — not a public API)
Relevant keys: `mining_target` (current target hex, JSON-string-encoded), `mining_height`
(current height, as string), `mining_last_adj_height` (last height a retarget was
applied at). Read via `getSetting`/written via `setSetting` (`lib/mining.ts:47-56`).
Don't write these directly from pool/miner code — they're only ever mutated through
the atomic RPCs during block claiming and retargeting.

### RPCs (Postgres functions called via Supabase `.rpc()`, not HTTP-exposed directly)
- `claim_mining_block(p_expected_height, p_hash, p_nonce, p_miner_id, p_previous_hash, p_target, p_reward_zites, p_pool_id)`
  — locks `mining_height`, inserts the block row, advances height, all in one
  transaction; raises/returns a height-mismatch signal (surfaced as the 409 collision)
  if `p_expected_height` no longer matches current height when it runs.
- `credit_zites_balance(p_user_id, p_amount)` — atomic `zites_balance += amount`.
- `apply_difficulty_retarget(p_new_adj_height, p_new_target)` — idempotent-per-height
  target update, returns whether it actually applied (false if that boundary height was
  already processed).

---

## 9. Notifications fired by the mining/pool system

All go through `createNotification()` (`lib/notifications.ts`), which inserts into the
`notifications` table (`user_id, type, title, body, link`). Types relevant to mining:

| type | fired when | recipient | link |
|---|---|---|---|
| `pool_activated` | liveness test passes | pool owner | `/mining/pools/{id}` |
| `pool_liveness_failed` | initial liveness test fails | pool owner | `/mining/pools/{id}` |
| `pool_offline` | 3 consecutive uptime-sweep failures | pool owner | `/mining/pools/{id}` |
| `pool_block_found` | pool submits a block successfully | pool owner (pool-level summary, always) | `/mining/pools/{id}` |
| `pool_reward` | pool submits a block successfully | **every user in the surviving `shares` list**, individually, with their own credited amount | `/mining/pools/{id}` |

There is no notification for solo-mined blocks — solo miners only see the credited
balance change and the public block feed.

---

## 10. Real-time block feed / UI display semantics

`app/api/mining/blocks/route.ts` serves both a paginated list (`?page=N`, 20/page, newest
first) and a single-block lookup (`?height=N`). The frontend (`/mine` and `/mining`,
via the shared `components/mining/live-blocks-feed.tsx`) subscribes to Supabase Realtime
`postgres_changes` INSERT events on `mining_blocks` to get new blocks the instant they're
claimed, then re-fetches that single block's full row (with joins) from the API.

**Pool-block anonymity**: as of this feature, blocks with a non-null `pool_id` are
displayed in the UI *without* exposing `miner_id`/the joined `users` record at all —
the card and detail dialog show a generic "Mined in pool: {pool name}" instead of any
person's identity. The `?height=N` lookup additionally attaches a `shares` array
(joined `mining_pool_shares` + `users`) to the response whenever `pool_id` is set, sorted
by `zites_credited` descending, so the UI can show a per-user split on expand. If you're
building anything that consumes this API (a dashboard, a bot), be aware: **the raw API
response still includes the joined `users` object for the block's `miner_id` even on
pool blocks** (it's the pool owner) — the anonymization is a frontend rendering choice,
not a backend redaction. Don't assume the API itself hides pool-owner identity; only the
shipped UI does.

---

## 11. Extras / gotchas for agents

- **Height races are normal, not exceptional.** Any time multiple miners/pools are
  live, expect frequent 409s. The correct response is always: re-fetch `GET /api/mining`,
  don't retry the stale submission, keep searching at the new target.
- **`hash` and `previous_hash` are case-sensitive strings server-side except where
  explicitly lowercased on insert** — the verification comparison does
  `expectedHash !== opts.hash.toLowerCase()`, i.e. it lowercases *your* submitted hash
  before comparing, but you should just always work in lowercase hex to avoid surprises
  elsewhere (e.g. `hash.toLowerCase()` is what actually gets stored).
- **Nonce type**: accept both numeric and numeric-string nonces on the way in; the
  server does `Number(nonce)` — don't send non-numeric strings.
- **`ip_version` is purely informational/validation metadata** — nothing in this repo's
  routes actually dials your pool differently based on it; it's stored and displayed
  but the liveness checker just calls `net.Socket.connect(port, host)` and lets Node
  resolve it however it resolves it.
- **A pool can be `pending` and still be joinable** (§7.10) — joining has no status
  gate. Only `submit-block` gates on `status === "active"`.
- **Deleting a pool doesn't delete its historical blocks**, only detaches them
  (`pool_id → NULL`). If you're writing analytics/audit tooling, don't assume a missing
  `pool_id` on an old block means it was solo-mined — check whether that could instead
  be an orphaned pool block, e.g. by cross-referencing `found_at` against known pool
  deletion times if that matters for your use case (there's no `deleted_pools` history
  table in this schema to check directly).
- **Rounding remainder sink**: see §7.11 step 6 — the *last* entry in your submitted
  `shares` array absorbs float rounding drift. If you always put the same participant
  last, they'll consistently receive the (tiny) rounding remainder; shuffle order if you
  want that to average out, or don't worry about it, it's sub-0.0001 Zites per block.
- **No rate limiting or captcha visible in these routes** — nothing in this codebase
  throttles submission attempts. Don't assume you need to back off; the natural rate
  limit is "how fast can you find a valid hash," same as any PoW system.
- **The pool API key is a bearer secret with no rotation endpoint** in this codebase.
  If asked to add key rotation, there currently isn't one to build on top of — you'd be
  adding a new route, not finding an existing one.
