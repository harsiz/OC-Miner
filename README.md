# OC-Miner

A fast, cross-platform (Windows/macOS/Linux) miner for [OmegaCases](https://omegacases.com), written in Go, plus a zero-dependency Node.js pool server for running your own pool from a VPS. Supports both **solo mining** (direct against the OmegaCases API) and **pool mining**.

- **`oc-miner-gpu`** — desktop GUI, GPU mining via OpenCL.
- **`oc-miner-gpu-cli`** — headless CLI, GPU mining, for servers/VPSes with a GPU but no display.
- **`oc-miner-cpu`** — headless CLI, multi-core CPU mining, for machines without a usable GPU/OpenCL driver.
- **`oc-pool.js`** — single-file Node.js pool server, interactive setup, built for SSH/VPS use.
- **`oc-pool-server`** — reference pool server in Go, if you'd rather not run Node.

GPU compute uses OpenCL, loaded dynamically at runtime via [purego](https://github.com/ebitengine/purego) — no OpenCL SDK/headers are needed to build this project, only a GPU driver with OpenCL support at run time. The GUI is built with [Fyne](https://fyne.io).

## Mining algorithm

Per OmegaCases' `/mine` page:

```
hash = SHA256(previous_hash + id_no_dashes + nonce)
```

- Solo mining: `id` is your OmegaCases user id.
- Pool mining: `id` is the pool's id (per `/developer/docs/mining-pools`).
- Target block time: 6 minutes. Difficulty adjusts every 10 blocks. Reward halves every 200 blocks.

Both the GPU kernel (`internal/gpu/kernel.cl`) and the CPU miner (`internal/cpu`, via `job.HashNonceFast`) exploit the fact that `previous_hash` is always exactly one 64-byte SHA-256 block: the CPU precomputes the compression midstate once per job, and each hash attempt only computes the second block (id + ascii nonce + padding), roughly halving the work per hash.

## Building

```sh
go build -o oc-miner-gpu ./cmd/oc-miner-gpu
go build -o oc-miner-gpu-cli ./cmd/oc-miner-gpu-cli
go build -o oc-miner-cpu ./cmd/oc-miner-cpu
go build -o oc-pool-server ./cmd/oc-pool-server
```

`oc-miner-gpu` requires a C compiler on PATH (cgo is used by Fyne for windowing/GL) — on Windows this can be MinGW-w64 or MSVC via `cgo`; on Linux install `gcc`, `libgl1-mesa-dev`, and `xorg-dev`; on macOS the Xcode command line tools are sufficient. OpenCL itself needs no headers, only a runtime driver, and is loaded dynamically at startup. `oc-miner-gpu-cli`, `oc-miner-cpu`, and `oc-pool-server` are headless and don't need any windowing deps (`oc-miner-gpu-cli` still needs a GPU driver with OpenCL support at runtime, just no display server).

`oc-pool.js` needs nothing but a Node.js runtime (`node oc-pool.js`, or `chmod +x` and run it directly on Linux) — no `npm install`, it only uses Node built-ins.

GitHub Actions (`.github/workflows/build.yml`) builds native binaries for Windows, macOS, and Linux on every push/tag using per-OS runners, and publishes a GitHub Release with all of them when a `v*` tag is pushed.

## Usage

### GPU miner (`oc-miner-gpu`)

1. Launch it, pick **Solo Mining** or **Pool Mining**.
2. Solo: enter the API URL (default `https://omegacases.com`) and your miner address (your OmegaCases user id).
   Pool: enter the pool's host/port and your OmegaCases user id (join the pool on the site first).
3. Click **Start Mining**.

### Headless CLI miners (`oc-miner-gpu-cli`, `oc-miner-cpu`)

Same flags on both — swap the binary name for GPU vs. CPU:

```sh
# solo
oc-miner-gpu-cli -mode solo -id <your-user-id> [-api https://omegacases.com]
oc-miner-cpu     -mode solo -id <your-user-id> [-api https://omegacases.com]

# pool
oc-miner-gpu-cli -mode pool -id <your-user-id> -pool-host <host> [-pool-port 3333]
oc-miner-cpu     -mode pool -id <your-user-id> -pool-host <host> [-pool-port 3333]
```

`oc-miner-cpu` uses every CPU core. Ctrl+C stops either one.

## Running your own pool

OmegaCases doesn't define a miner↔pool wire protocol — operators are free to build anything, as long as the pool answers OmegaCases's raw `PING` liveness probe with `PONG` and calls `submit-block` when it solves a block. This repo defines and implements one: the **OC-Miner Pool Protocol v1**, a small newline-delimited JSON protocol (see below), spoken by both pool servers here and by every miner here (`oc-miner-gpu`, `oc-miner-gpu-cli`, `oc-miner-cpu`).

### Option A: `oc-pool.js` (Node, recommended for a VPS over SSH)

```sh
node oc-pool.js
```

First run asks a few questions (pool name, your OmegaCases user id, port, public host — it'll try to auto-detect your public IP as a default, API URL, share difficulty factor), registers the pool with OmegaCases, saves everything to `oc-pool-config.json` next to the script, and starts serving. Every run after that reads the saved config and starts straight up — no re-registration, no re-prompting. Leave it running in `tmux`/`screen`, or wrap it in a `systemd` unit calling `node /path/to/oc-pool.js`.

It binds its listening port *before* calling the registration API, so OmegaCases's liveness probe never hits a closed port during setup.

### Option B: `oc-pool-server` (Go)

Registration isn't automated here — do it yourself first:

```sh
curl -X POST https://omegacases.com/api/mining/pools \
  -H "Content-Type: application/json" \
  -d '{"owner_id":"your-user-id","name":"My Pool","host":"203.0.113.10","port":3333,"ip_version":"auto"}'
```

Save the returned `api_key` (shown once), then:

```sh
oc-pool-server -listen 0.0.0.0:3333 -pool-id <uuid> -api-key <key>
```

### Either way

Once OmegaCases's liveness checks pass, your pool goes `active` and appears on `/mining`. Miners join on the site, then point their miner at your host/port.

The server assigns miners an easier "share" target (a configurable multiple of the real network target — `-share-factor` for the Go server, the "share difficulty factor" prompt for the Node one; default 4096 either way) so it can track proportional contribution; when any submitted share also happens to meet the real network target, the pool has found a block and calls `submit-block` with the accumulated share counts. Payout logic beyond that (thresholds, PPLNS windows, etc.) is intentionally left simple here — see the docs, this is OmegaCases's design: the pool operator owns that logic entirely.

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
cmd/oc-miner-gpu/     desktop GUI miner (Fyne), GPU mining
cmd/oc-miner-gpu-cli/ headless CLI miner, GPU mining
cmd/oc-miner-cpu/     headless CLI miner, multi-core CPU mining
cmd/oc-pool-server/   reference pool server (Go)
node-pool/oc-pool.js  single-file Node.js pool server
internal/job/         preimage/midstate construction, CPU reference hashing
internal/gpu/         OpenCL bindings (purego) + kernel.cl + Device implementation
internal/cpu/         multi-core CPU Device implementation
internal/minerdevice/ shared Device interface driven by solo/poolclient
internal/clirunner/   shared flag parsing + mining loop wiring for the headless CLIs
internal/solo/        solo mining loop against the OmegaCases API
internal/poolclient/  pool mining loop (OC-Miner Pool Protocol v1 client)
internal/protocol/    shared JSON message types for the pool protocol
internal/engine/      shared UI-facing message/stats types
```
