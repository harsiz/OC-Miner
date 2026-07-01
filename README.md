# OC-Miner (GPU)

A fast, cross-platform (Windows/macOS/Linux) GPU miner for [OmegaCases](https://omegacases.com), written in Go. Supports both **solo mining** (direct against the OmegaCases API) and **pool mining**.

GPU compute uses OpenCL, loaded dynamically at runtime via [purego](https://github.com/ebitengine/purego) — no OpenCL SDK/headers are needed to build this project, only a GPU driver with OpenCL support at run time. The UI is built with [Fyne](https://fyne.io).

## Mining algorithm

Per OmegaCases' `/mine` page:

```
hash = SHA256(previous_hash + id_no_dashes + nonce)
```

- Solo mining: `id` is your OmegaCases user id.
- Pool mining: `id` is the pool's id (per `/developer/docs/mining-pools`).
- Target block time: 6 minutes. Difficulty adjusts every 10 blocks. Reward halves every 200 blocks.

The GPU kernel (`internal/gpu/kernel.cl`) exploits the fact that `previous_hash` is always exactly one 64-byte SHA-256 block: the CPU precomputes the compression midstate once per job, and each GPU work-item only computes the second block (id + ascii nonce + padding), roughly halving the work per hash.

## Building

```sh
go build -o oc-miner-gpu ./cmd/oc-miner-gpu
go build -o oc-pool-server ./cmd/oc-pool-server
```

Requires a C compiler on PATH (cgo is used by Fyne for windowing/GL) — on Windows this can be MinGW-w64 or MSVC via `cgo`; on Linux install `gcc`, `libgl1-mesa-dev`, and `xorg-dev`; on macOS the Xcode command line tools are sufficient. OpenCL itself needs no headers, only a runtime driver, and is loaded dynamically at startup.

GitHub Actions (`.github/workflows/build.yml`) builds native binaries for Windows, macOS, and Linux on every push/tag using per-OS runners, and publishes a GitHub Release with all three when a `v*` tag is pushed.

## Usage

### Solo mining

1. Launch `oc-miner-gpu`, select **Solo Mining**.
2. Enter the OmegaCases API URL (default `https://omegacases.com`) and your miner address (your OmegaCases user id).
3. Click **Start Mining**.

### Pool mining

1. Find a pool on [omegacases.com/mining](https://omegacases.com/mining) (or run your own, see below) and join it on the site.
2. Launch `oc-miner-gpu`, select **Pool Mining**, enter the pool's host/port and your OmegaCases user id.
3. Click **Start Mining**.

## Running your own pool

OmegaCases doesn't define a miner↔pool wire protocol — operators are free to build anything, as long as the pool answers OmegaCases's raw `PING` liveness probe with `PONG` and calls `submit-block` when it solves a block. This repo defines and implements one: the **OC-Miner Pool Protocol v1** (`internal/protocol`), a small newline-delimited JSON protocol, and ships a reference server that speaks it, `oc-pool-server`.

1. Register a pool per [/developer/docs/mining-pools](https://omegacases.com/developer/docs/mining-pools):
   ```sh
   curl -X POST https://omegacases.com/api/mining/pools \
     -H "Content-Type: application/json" \
     -d '{"owner_id":"your-user-id","name":"My Pool","host":"203.0.113.10","port":3333,"ip_version":"auto"}'
   ```
   Save the returned `api_key` — it's shown once.
2. Run the server with the returned pool id and API key:
   ```sh
   oc-pool-server -listen 0.0.0.0:3333 -pool-id <uuid> -api-key <key>
   ```
3. Once OmegaCases's liveness checks pass, your pool goes `active` and appears on `/mining`. Miners join on the site, then point their miner at your host/port.

The server assigns miners an easier "share" target (a configurable multiple of the real network target, `-share-factor`, default 4096) so it can track proportional contribution; when any submitted share also happens to meet the real network target, the pool has found a block and calls `submit-block` with the accumulated share counts. Payout logic beyond that (thresholds, PPLNS windows, etc.) is intentionally left simple here — see the docs, this is OmegaCases's design: the pool operator owns that logic entirely.

### OC-Miner Pool Protocol v1

Newline-delimited JSON, either direction, distinct from OmegaCases's raw `PING`/`PONG` liveness check (which the pool server handles first, before falling through to this protocol):

| Direction | Message |
|---|---|
| miner → pool | `{"type":"hello","user_id":"..."}` |
| pool → miner | `{"type":"job","pool_id":"...","previous_hash":"...","target":"..."}` |
| miner → pool | `{"type":"share","nonce":123,"hash":"..."}` |
| pool → miner | `{"type":"share_result","accepted":true,"message":"..."}` |
| pool → miner | `{"type":"ping"}` |
| miner → pool | `{"type":"pong"}` |

## Project layout

```
cmd/oc-miner-gpu/    desktop GUI miner (Fyne)
cmd/oc-pool-server/  reference pool server
internal/job/        preimage/midstate construction, CPU reference hashing
internal/gpu/        OpenCL bindings (purego) + kernel.cl + Miner wrapper
internal/solo/       solo mining loop against the OmegaCases API
internal/poolclient/ pool mining loop (OC-Miner Pool Protocol v1 client)
internal/protocol/   shared JSON message types for the pool protocol
internal/engine/     shared UI-facing message/stats types
```
