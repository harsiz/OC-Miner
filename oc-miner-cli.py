#!/usr/bin/env python3
import hashlib
import requests
import argparse
import multiprocessing
import time
import sys
import os
from datetime import datetime


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


# ── WORKER (module level for pickling on Windows) ────────────────────────────
def _worker(prev_hash, miner_id_clean, target, core_id, num_cores,
            result_queue, stop_event, rate_queue):
    import hashlib, time
    prefix  = (prev_hash + miner_id_clean).encode()
    nonce   = core_id
    batch   = 5000
    count   = 0
    t0      = time.time()

    while not stop_event.is_set():
        nonce_b = str(nonce).encode()
        h       = hashlib.sha256(prefix + nonce_b).hexdigest()
        count  += 1

        if h < target:
            preimage = prev_hash + miner_id_clean + str(nonce)
            result_queue.put((nonce, h, preimage))
            return

        if count >= batch:
            now  = time.time()
            rate = count / (now - t0)
            rate_queue.put((rate, count))
            count = 0
            t0    = now

        nonce += num_cores


# ── MAIN MINE FUNCTION ───────────────────────────────────────────────────────
def mine(api, miner_id):
    api            = api.rstrip("/")
    miner_id_clean = miner_id.replace("-", "")
    num_cores      = os.cpu_count() or 1
    session_hashes = 0
    session_blocks = 0
    session_start  = time.time()

    log("Starting miner")
    log(f"Address : {miner_id}")
    log(f"API     : {api}")
    log(f"Cores   : {num_cores}")
    log("=" * 60)

    while True:
        try:
            log("Fetching block template...")
            resp = requests.get(f"{api}/api/mining", timeout=10)
            resp.raise_for_status()
            info = resp.json()

            target    = info.get("target", "")
            prev_hash = info.get("previous_hash", "")

            log(f"Target   : {target}")
            log(f"Prev hash: {prev_hash}")
            log(f"Mining on {num_cores} core(s)...")

            result_queue = multiprocessing.Queue()
            stop_event   = multiprocessing.Event()
            rate_queue   = multiprocessing.Queue()

            workers = []
            for core_id in range(num_cores):
                p = multiprocessing.Process(
                    target=_worker,
                    args=(prev_hash, miner_id_clean, target,
                          core_id, num_cores, result_queue,
                          stop_event, rate_queue),
                    daemon=True
                )
                p.start()
                workers.append(p)

            t0         = time.time()
            last_print = time.time()
            last_check = time.time()
            found      = False

            while True:
                now = time.time()

                # Drain rate reports
                total_rate   = 0.0
                total_hashes = 0
                try:
                    while True:
                        r, h_count    = rate_queue.get_nowait()
                        total_rate   += r
                        total_hashes += h_count
                except Exception:
                    pass
                if total_hashes:
                    session_hashes += total_hashes

                # Print live stats every 2s
                if now - last_print >= 2.0:
                    last_print = now
                    hr   = total_rate
                    unit = "MH/s" if hr >= 1_000_000 else ("KH/s" if hr >= 1000 else "H/s")
                    val  = hr / 1_000_000 if hr >= 1_000_000 else (hr / 1000 if hr >= 1000 else hr)
                    elapsed = int(now - session_start)
                    h2, rem = divmod(elapsed, 3600)
                    m2, s2  = divmod(rem, 60)
                    print(
                        f"\r  {val:.2f} {unit} | "
                        f"Nonces: {session_hashes:,} | "
                        f"Blocks: {session_blocks} | "
                        f"Uptime: {h2:02}:{m2:02}:{s2:02}   ",
                        end="", flush=True
                    )

                # Check if worker found block
                try:
                    nonce, h, preimage = result_queue.get_nowait()
                    found = True
                except Exception:
                    nonce = h = preimage = None

                if found:
                    print()
                    elapsed_block = now - t0
                    verify_h      = hashlib.sha256(preimage.encode()).hexdigest()
                    log(f"Block found! Nonce={nonce}  Hash={h}", "FOUND")
                    log(f"  DEBUG preimage : {preimage}")
                    log(f"  DEBUG hash     : {h}")
                    log(f"  DEBUG verify   : {verify_h}")
                    log(f"  DEBUG match    : {h == verify_h}")
                    log("Submitting...", "INFO")

                    try:
                        res = requests.post(f"{api}/api/mining", json={
                            "miner_id": miner_id,
                            "nonce":    nonce,
                            "hash":     h
                        }, timeout=10)
                        if res.status_code == 200:
                            session_blocks += 1
                            log(f"Block accepted! ({elapsed_block:.2f}s) {res.json()}", "OK")
                        elif res.status_code == 409:
                            log("Stale — another miner was faster. Restarting...", "WARN")
                            log(f"  Body: {res.text}", "WARN")
                        else:
                            log(f"Server returned {res.status_code}", "ERROR")
                            log(f"  Body: {res.text}", "ERROR")
                    except Exception as e:
                        log(f"Submit error: {e}", "ERROR")
                    break

                # Poll for new block every 20s
                if now - last_check >= 20.0:
                    last_check = now
                    try:
                        check = requests.get(f"{api}/api/mining", timeout=5).json()
                        if check.get("previous_hash") != prev_hash:
                            print()
                            log("New block detected — restarting...", "WARN")
                            stop_event.set()
                            break
                    except Exception:
                        pass

                time.sleep(0.05)

            # clean up
            stop_event.set()
            for p in workers:
                p.join(timeout=2)
                if p.is_alive():
                    p.terminate()

        except requests.exceptions.RequestException as e:
            print()
            log(f"Network error: {e}", "ERROR")
            log("Retrying in 5s...", "WARN")
            time.sleep(5)
        except KeyboardInterrupt:
            print()
            log("Stopped by user.")
            sys.exit(0)
        except Exception as e:
            print()
            log(f"Unexpected error: {e}", "ERROR")
            time.sleep(5)


def main():
    parser = argparse.ArgumentParser(
        description="OmegaCases SHA-256 CLI Miner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python miner_cli.py --api https://omegacases.com --id 44c7a80f-a8f8-44f7-8e51-810577df3ca6"
    )
    parser.add_argument("--api", required=True, help="API base URL")
    parser.add_argument("--id",  required=True, help="Your miner address / UUID")
    args = parser.parse_args()
    mine(args.api, args.id)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
