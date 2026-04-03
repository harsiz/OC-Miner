#!/usr/bin/env python3
import hashlib
import requests
import argparse
import time
import sys
from datetime import datetime

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

def mine(api, miner_id):
    api = api.rstrip("/")
    miner_id_clean = miner_id.replace("-", "")
    session_hashes = 0
    session_blocks = 0
    session_start  = time.time()

    log(f"Starting miner")
    log(f"Address : {miner_id}")
    log(f"API     : {api}")
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
            log("Mining...")

            nonce      = 0
            t0         = time.time()
            last_rate  = time.time()
            rate_count = 0

            while True:
                preimage = f"{prev_hash}{miner_id_clean}{nonce}"
                h = hashlib.sha256(preimage.encode()).hexdigest()
                rate_count     += 1
                session_hashes += 1

                now = time.time()
                if now - last_rate >= 2.0:
                    hr = rate_count / (now - last_rate)
                    unit = "KH/s" if hr >= 1000 else "H/s"
                    val  = hr / 1000 if hr >= 1000 else hr
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
                    rate_count = 0
                    last_rate  = now

                if h < target:
                    print()  # newline after the live rate line
                    elapsed_block = time.time() - t0
                    verify_h = hashlib.sha256(preimage.encode()).hexdigest()
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

                nonce += 1

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
    parser.add_argument("--api", required=True,  help="API base URL  (e.g. https://omegacases.com)")
    parser.add_argument("--id",  required=True,  help="Your miner address / UUID")
    args = parser.parse_args()
    mine(args.api, args.id)

if __name__ == "__main__":
    main()
