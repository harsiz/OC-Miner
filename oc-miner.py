import tkinter as tk
from tkinter import ttk, scrolledtext
import hashlib
import requests
import threading
import time
import queue
from datetime import datetime

# ── Colours (Bitcoin Core light palette) ──────────────────────────────────────
BG         = "#F5F5F5"
BG2        = "#FFFFFF"
BG3        = "#EBEBEB"
BORDER     = "#CCCCCC"
ACCENT     = "#F7931A"        # Bitcoin orange
ACCENT2    = "#E07B00"
TEXT       = "#1A1A1A"
TEXT2      = "#555555"
TEXT3      = "#888888"
GREEN      = "#1A9A1A"
RED        = "#CC2200"
FONT_MONO  = ("Courier New", 9)
FONT_MONO2 = ("Courier New", 8)
FONT_UI    = ("Segoe UI", 9)
FONT_UI_B  = ("Segoe UI", 9, "bold")
FONT_TITLE = ("Segoe UI", 11, "bold")
FONT_STAT  = ("Courier New", 14, "bold")
FONT_SMALL = ("Segoe UI", 8)


# ── MULTIPROCESSING WORKER (module level, picklable) ─────────────────────────
def _worker(prev_hash, miner_id_clean, target, core_id, num_cores,
            result_queue, stop_event, rate_queue):
    """Each worker owns a slice of the nonce space: core_id, core_id+num_cores, ..."""
    import hashlib, time
    prefix      = (prev_hash + miner_id_clean).encode()
    nonce       = core_id
    batch       = 5000          # hashes per rate-report batch
    count       = 0
    t0          = time.time()

    while not stop_event.is_set():
        nonce_b  = str(nonce).encode()
        h        = hashlib.sha256(prefix + nonce_b).hexdigest()
        count   += 1

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

        nonce += num_cores   # stride by num_cores so workers never overlap



class OmegaMiner:
    def __init__(self, root):
        self.root = root
        self.root.title("OmegaCases Miner  v1.0.0")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        # state
        self.mining       = False
        self.miner_thread = None
        self.log_queue    = queue.Queue()
        self.stat_queue   = queue.Queue()

        # session stats
        self.session_hashes  = 0
        self.session_blocks  = 0
        self.session_start   = None
        self.hash_rate       = 0.0
        self.last_block_hash = "—"
        self.current_target  = "—"
        self.status_text     = "Idle"

        self._build_ui()
        self._poll_queues()

    # ── UI BUILD ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_menu()
        main = tk.Frame(self.root, bg=BG, padx=12, pady=10)
        main.pack(fill="both", expand=True)

        self._build_title_bar(main)
        self._build_config(main)
        self._build_stats(main)
        self._build_controls(main)
        self._build_log(main)
        self._build_statusbar()

    def _build_menu(self):
        mb = tk.Menu(self.root, bg=BG2, fg=TEXT, activebackground=ACCENT,
                     activeforeground="white", relief="flat", bd=0)
        self.root.config(menu=mb)
        file_m = tk.Menu(mb, tearoff=0, bg=BG2, fg=TEXT,
                         activebackground=ACCENT, activeforeground="white")
        file_m.add_command(label="Clear Log", command=self._clear_log)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self.root.quit)
        mb.add_cascade(label="File", menu=file_m)

    def _build_title_bar(self, parent):
        bar = tk.Frame(parent, bg=BG2, relief="flat",
                       highlightbackground=BORDER, highlightthickness=1)
        bar.pack(fill="x", pady=(0, 8))

        inner = tk.Frame(bar, bg=BG2, padx=12, pady=8)
        inner.pack(fill="x")

        # Logo + title
        logo_frame = tk.Frame(inner, bg=BG2)
        logo_frame.pack(side="left")

        logo = tk.Label(logo_frame, text="⛏", font=("Segoe UI", 20),
                        bg=BG2, fg=ACCENT)
        logo.pack(side="left", padx=(0, 8))

        title_sub = tk.Frame(logo_frame, bg=BG2)
        title_sub.pack(side="left")
        tk.Label(title_sub, text="OmegaCases Miner", font=FONT_TITLE,
                 bg=BG2, fg=TEXT).pack(anchor="w")
        tk.Label(title_sub, text="SHA-256 Proof-of-Work Client  v1.0.0",
                 font=FONT_SMALL, bg=BG2, fg=TEXT3).pack(anchor="w")

        # Status pill
        pill = tk.Frame(inner, bg=BG3,
                        highlightbackground=BORDER, highlightthickness=1)
        pill.pack(side="right")
        self.status_dot = tk.Label(pill, text="●", font=("Segoe UI", 10),
                                   bg=BG3, fg=TEXT3, padx=8, pady=4)
        self.status_dot.pack(side="left")
        self.status_lbl = tk.Label(pill, text="Offline", font=FONT_UI,
                                   bg=BG3, fg=TEXT3, padx=6, pady=4)
        self.status_lbl.pack(side="left")

    def _build_config(self, parent):
        frame = tk.LabelFrame(parent, text="  Configuration  ",
                              bg=BG, fg=TEXT2, font=FONT_UI,
                              relief="flat",
                              highlightbackground=BORDER, highlightthickness=1,
                              padx=10, pady=8)
        frame.pack(fill="x", pady=(0, 8))

        # API URL
        row1 = tk.Frame(frame, bg=BG)
        row1.pack(fill="x", pady=(0, 6))
        tk.Label(row1, text="API URL", font=FONT_UI_B,
                 bg=BG, fg=TEXT, width=14, anchor="w").pack(side="left")
        self.api_var = tk.StringVar(value="https://omegacases.com")
        self.api_entry = tk.Entry(row1, textvariable=self.api_var,
                                  font=FONT_MONO, bg=BG2, fg=TEXT,
                                  insertbackground=TEXT,
                                  relief="flat",
                                  highlightbackground=BORDER,
                                  highlightthickness=1)
        self.api_entry.pack(side="left", fill="x", expand=True)

        # Miner ID
        row2 = tk.Frame(frame, bg=BG)
        row2.pack(fill="x")
        tk.Label(row2, text="Miner Address", font=FONT_UI_B,
                 bg=BG, fg=TEXT, width=14, anchor="w").pack(side="left")
        self.id_var = tk.StringVar(value="")
        self.id_entry = tk.Entry(row2, textvariable=self.id_var,
                                 font=FONT_MONO, bg=BG2, fg=TEXT,
                                 insertbackground=TEXT,
                                 relief="flat",
                                 highlightbackground=BORDER,
                                 highlightthickness=1)
        self.id_entry.pack(side="left", fill="x", expand=True)
        tk.Label(row2, text="Paste your address",
                 font=FONT_SMALL, bg=BG, fg=TEXT3, padx=6).pack(side="left")

    def _build_stats(self, parent):
        frame = tk.LabelFrame(parent, text="  Mining Statistics  ",
                              bg=BG, fg=TEXT2, font=FONT_UI,
                              relief="flat",
                              highlightbackground=BORDER, highlightthickness=1,
                              padx=10, pady=10)
        frame.pack(fill="x", pady=(0, 8))

        grid = tk.Frame(frame, bg=BG)
        grid.pack(fill="x")

        def stat_card(parent, col, label, val_default, color=TEXT):
            card = tk.Frame(parent, bg=BG2,
                            highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=0, column=col, padx=(0 if col == 0 else 6, 0),
                      sticky="nsew")
            parent.columnconfigure(col, weight=1)
            tk.Label(card, text=label, font=FONT_SMALL,
                     bg=BG2, fg=TEXT3, pady=6, padx=10).pack(anchor="w")
            var = tk.StringVar(value=val_default)
            tk.Label(card, textvariable=var, font=FONT_STAT,
                     bg=BG2, fg=color, padx=10, pady=4).pack(anchor="w")
            return var

        self.hs_var     = stat_card(grid, 0, "Hash Rate",     "0.00 H/s",  ACCENT)
        self.blocks_var = stat_card(grid, 1, "Blocks Found",  "0",         GREEN)
        self.nonces_var = stat_card(grid, 2, "Nonces Tried",  "0",         TEXT)
        self.uptime_var = stat_card(grid, 3, "Session Time",  "00:00:00",  TEXT2)

        # second row – wider info
        row2 = tk.Frame(frame, bg=BG)
        row2.pack(fill="x", pady=(8, 0))

        def info_field(parent, label, var_default):
            f = tk.Frame(parent, bg=BG)
            f.pack(fill="x", pady=2)
            tk.Label(f, text=label, font=FONT_UI_B,
                     bg=BG, fg=TEXT2, width=16, anchor="w").pack(side="left")
            var = tk.StringVar(value=var_default)
            tk.Label(f, textvariable=var, font=FONT_MONO2,
                     bg=BG, fg=TEXT).pack(side="left")
            return var

        self.target_var   = info_field(row2, "Current Target",   "—")
        self.lasthash_var = info_field(row2, "Last Block Hash",  "—")

    def _build_controls(self, parent):
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill="x", pady=(0, 8))

        btn_cfg = dict(font=("Segoe UI", 10, "bold"),
                       relief="flat", cursor="hand2",
                       bd=0, padx=20, pady=8)

        self.start_btn = tk.Button(frame, text="▶  Start Mining",
                                   bg=ACCENT, fg="white",
                                   activebackground=ACCENT2,
                                   activeforeground="white",
                                   command=self._start_mining, **btn_cfg)
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = tk.Button(frame, text="■  Stop",
                                  bg=BG3, fg=TEXT,
                                  activebackground=BORDER,
                                  activeforeground=TEXT,
                                  state="disabled",
                                  command=self._stop_mining, **btn_cfg)
        self.stop_btn.pack(side="left")

        tk.Button(frame, text="Clear Log",
                  bg=BG3, fg=TEXT2,
                  activebackground=BORDER,
                  activeforeground=TEXT,
                  command=self._clear_log, **btn_cfg).pack(side="right")

    def _build_log(self, parent):
        frame = tk.LabelFrame(parent, text="  Debug Log  ",
                              bg=BG, fg=TEXT2, font=FONT_UI,
                              relief="flat",
                              highlightbackground=BORDER, highlightthickness=1,
                              padx=6, pady=6)
        frame.pack(fill="both", expand=True)

        self.log = scrolledtext.ScrolledText(
            frame, height=14, font=FONT_MONO2,
            bg=BG2, fg=TEXT, insertbackground=TEXT,
            relief="flat", state="disabled",
            wrap="word"
        )
        self.log.pack(fill="both", expand=True)

        # tag colours
        self.log.tag_config("ts",    foreground=TEXT3)
        self.log.tag_config("info",  foreground=TEXT2)
        self.log.tag_config("ok",    foreground=GREEN)
        self.log.tag_config("warn",  foreground=ACCENT)
        self.log.tag_config("error", foreground=RED)
        self.log.tag_config("head",  foreground=ACCENT, font=FONT_UI_B)

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG3,
                       highlightbackground=BORDER, highlightthickness=1)
        bar.pack(fill="x", side="bottom")
        self.statusbar_lbl = tk.Label(
            bar, text="Ready.", font=FONT_SMALL,
            bg=BG3, fg=TEXT3, anchor="w", padx=8, pady=3)
        self.statusbar_lbl.pack(side="left")
        tk.Label(bar, text="OmegaCases SHA-256 Miner",
                 font=FONT_SMALL, bg=BG3, fg=TEXT3, padx=8).pack(side="right")

    # ── LOGGING ─────────────────────────────────────────────────────────────────
    def _log(self, msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put((ts, msg, tag))

    def _flush_log(self, ts, msg, tag):
        self.log.configure(state="normal")
        self.log.insert("end", f"[{ts}] ", "ts")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ── STATUS BAR / PILL ───────────────────────────────────────────────────────
    def _set_status(self, text, color=TEXT3):
        self.status_lbl.config(text=text, fg=color)
        self.status_dot.config(fg=color)
        self.statusbar_lbl.config(text=text)

    # ── CONTROLS ────────────────────────────────────────────────────────────────
    def _start_mining(self):
        api = self.api_var.get().strip().rstrip("/")
        mid = self.id_var.get().strip()
        if not api:
            self._log("API URL is required.", "error"); return
        if not mid:
            self._log("Miner address is required.", "error"); return

        self.mining = True
        self.session_hashes = 0
        self.session_blocks = 0
        self.session_start  = time.time()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.api_entry.config(state="disabled")
        self.id_entry.config(state="disabled")

        self._set_status("Mining…", ACCENT)
        self._log("=" * 58, "head")
        self._log(f"Starting miner | Address: {mid}", "head")
        self._log(f"API: {api}", "info")
        self._log("=" * 58, "head")

        self.miner_thread = threading.Thread(
            target=self._mine_loop, args=(api, mid), daemon=True)
        self.miner_thread.start()

    def _stop_mining(self):
        self.mining = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.api_entry.config(state="normal")
        self.id_entry.config(state="normal")
        self._set_status("Stopped", RED)
        self._log("Mining stopped by user.", "warn")

    # ── MINING LOOP (background thread) ─────────────────────────────────────────
    def _mine_loop(self, api, miner_id):
        while self.mining:
            try:
                self._log("Fetching new block template…", "info")
                resp = requests.get(f"{api}/api/mining", timeout=10)
                resp.raise_for_status()
                info = resp.json()

                target    = info.get("target", "")
                prev_hash = info.get("previous_hash", "")

                self.stat_queue.put(("target", target))
                self._log(f"Target:    {target}", "info")
                self._log(f"Prev hash: {prev_hash}", "info")

                miner_id_clean = miner_id.replace("-", "")

                # pre-hash the static prefix once — big speedup
                prefix     = (prev_hash + miner_id_clean).encode()
                base_hash  = hashlib.sha256(prefix)

                nonce      = 0
                t0         = time.time()
                last_rate  = time.time()
                last_check = time.time()
                rate_count = 0

                while self.mining:
                    s = base_hash.copy()
                    s.update(str(nonce).encode())
                    h = s.hexdigest()
                    rate_count          += 1
                    self.session_hashes += 1

                    now = time.time()

                    # Update hashrate every 0.5s
                    if now - last_rate >= 0.5:
                        self.hash_rate = rate_count / (now - last_rate)
                        rate_count  = 0
                        last_rate   = now
                        self.stat_queue.put(("rate",   self.hash_rate))
                        self.stat_queue.put(("nonces", self.session_hashes))

                    # Poll for new block every 20s
                    if now - last_check >= 20.0:
                        last_check = now
                        try:
                            check = requests.get(f"{api}/api/mining", timeout=5).json()
                            if check.get("previous_hash") != prev_hash:
                                self._log("⟳ New block detected — restarting…", "warn")
                                break
                        except Exception:
                            pass

                    if h < target:
                        elapsed  = now - t0
                        preimage = prev_hash + miner_id_clean + str(nonce)
                        verify_h = hashlib.sha256(preimage.encode()).hexdigest()
                        self._log(f"✔ Block found! Nonce={nonce}  Hash={h}", "ok")
                        self._log(f"  DEBUG preimage: {preimage}", "info")
                        self._log(f"  DEBUG hash:     {h}", "info")
                        self._log(f"  DEBUG verify:   {verify_h}", "info")
                        self._log(f"  DEBUG match:    {h == verify_h}", "info")
                        self._log("  Submitting…", "info")
                        try:
                            res = requests.post(f"{api}/api/mining", json={
                                "miner_id": miner_id,
                                "nonce":    nonce,
                                "hash":     h
                            }, timeout=10)
                            if res.status_code == 200:
                                self.session_blocks += 1
                                self.stat_queue.put(("block", h))
                                self._log(f"✔ Block accepted! ({elapsed:.2f}s) {res.json()}", "ok")
                            elif res.status_code == 409:
                                self._log("✘ Stale — another miner was faster. Restarting…", "warn")
                                self._log(f"  Body: {res.text}", "warn")
                            else:
                                self._log(f"✘ Server returned {res.status_code}", "error")
                                self._log(f"  Body: {res.text}", "error")
                        except Exception as e:
                            self._log(f"Submit error: {e}", "error")
                        break

                    nonce += 1

            except requests.exceptions.RequestException as e:
                self._log(f"Network error: {e}", "error")
                self._log("Retrying in 5s…", "warn")
                time.sleep(5)
            except Exception as e:
                self._log(f"Unexpected error: {e}", "error")
                time.sleep(5)

        self.stat_queue.put(("rate", 0.0))

    # ── QUEUE POLLING (main thread) ──────────────────────────────────────────────
    def _poll_queues(self):
        # drain log queue
        try:
            while True:
                ts, msg, tag = self.log_queue.get_nowait()
                self._flush_log(ts, msg, tag)
        except queue.Empty:
            pass

        # drain stat queue
        try:
            while True:
                item = self.stat_queue.get_nowait()
                kind = item[0]
                if kind == "rate":
                    hr = item[1]
                    if hr >= 1000:
                        self.hs_var.set(f"{hr/1000:.2f} KH/s")
                    else:
                        self.hs_var.set(f"{hr:.1f} H/s")
                elif kind == "nonces":
                    n = item[1]
                    self.nonces_var.set(f"{n:,}")
                elif kind == "block":
                    self.blocks_var.set(str(self.session_blocks))
                    self.lasthash_var.set(item[1][:48] + "…")
                elif kind == "target":
                    self.target_var.set(item[1][:48] + "…" if len(item[1]) > 48 else item[1])
        except queue.Empty:
            pass

        # uptime
        if self.session_start and self.mining:
            elapsed = int(time.time() - self.session_start)
            h, rem  = divmod(elapsed, 3600)
            m, s    = divmod(rem, 60)
            self.uptime_var.set(f"{h:02}:{m:02}:{s:02}")

        self.root.after(200, self._poll_queues)


# ── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("720x680")
    app = OmegaMiner(root)
    root.mainloop()
