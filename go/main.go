package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"bytes"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"
)

// ── Colours ──────────────────────────────────────────────────────────────────
var (
	colAccent = color.NRGBA{R: 247, G: 147, B: 26, A: 255}  // Bitcoin orange
	colGreen  = color.NRGBA{R: 26, G: 154, B: 26, A: 255}
	colRed    = color.NRGBA{R: 204, G: 34, B: 0, A: 255}
	colGrey   = color.NRGBA{R: 136, G: 136, B: 136, A: 255}
)

// ── Mining state ─────────────────────────────────────────────────────────────
type Miner struct {
	mining      atomic.Bool
	stopChan    chan struct{}
	mu          sync.Mutex

	totalHashes atomic.Int64
	blocksFound atomic.Int64
	hashRate    atomic.Int64 // hashes per second * 100 for 2dp
	sessionStart time.Time

	// UI refs
	hsLabel      *widget.Label
	blocksLabel  *widget.Label
	noncesLabel  *widget.Label
	uptimeLabel  *widget.Label
	targetLabel  *widget.Label
	statusDot    *canvas.Text
	statusLabel  *widget.Label
	logList      *widget.List
	logEntries   []string
	logMu        sync.Mutex

	apiEntry *widget.Entry
	idEntry  *widget.Entry
}

func newMiner() *Miner {
	return &Miner{
		logEntries: []string{},
		stopChan:   make(chan struct{}),
	}
}

func (m *Miner) log(msg string) {
	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", ts, msg)
	m.logMu.Lock()
	m.logEntries = append(m.logEntries, entry)
	m.logMu.Unlock()
	if m.logList != nil {
		m.logList.Refresh()
		m.logList.ScrollToBottom()
	}
}

func (m *Miner) setStatus(text string, col color.Color) {
	if m.statusLabel != nil {
		m.statusLabel.SetText(text)
	}
	if m.statusDot != nil {
		m.statusDot.Color = col
		m.statusDot.Refresh()
	}
}

func formatHashRate(hs float64) string {
	switch {
	case hs >= 1_000_000_000:
		return fmt.Sprintf("%.2f GH/s", hs/1_000_000_000)
	case hs >= 1_000_000:
		return fmt.Sprintf("%.2f MH/s", hs/1_000_000)
	case hs >= 1_000:
		return fmt.Sprintf("%.2f KH/s", hs/1_000)
	default:
		return fmt.Sprintf("%.1f H/s", hs)
	}
}

// ── Mining logic ──────────────────────────────────────────────────────────────
type blockInfo struct {
	Target       string `json:"target"`
	PreviousHash string `json:"previous_hash"`
}

func (m *Miner) fetchBlock(api string) (*blockInfo, error) {
	resp, err := http.Get(api + "/api/mining")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info blockInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

type foundBlock struct {
	nonce   uint64
	hash    string
	preimage string
}

func (m *Miner) workerRange(prefix []byte, target string, startNonce, stride uint64, found chan<- foundBlock, stop <-chan struct{}, hashes *atomic.Int64) {
	nonce := startNonce
	batch := uint64(10000)
	local := uint64(0)

	for {
		select {
		case <-stop:
			hashes.Add(int64(local))
			return
		default:
		}

		nonceStr := fmt.Sprintf("%d", nonce)
		data := append(prefix, []byte(nonceStr)...)
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])

		if h < target {
			select {
			case found <- foundBlock{nonce: nonce, hash: h, preimage: string(prefix) + nonceStr}:
			default:
			}
			hashes.Add(int64(local) + 1)
			return
		}

		local++
		if local%batch == 0 {
			hashes.Add(int64(batch))
			local = 0
		}
		nonce += stride
	}
}

func (m *Miner) mineBlock(api, minerID string) bool {
	info, err := m.fetchBlock(api)
	if err != nil {
		m.log("Network error: " + err.Error())
		m.log("Retrying in 5s...")
		time.Sleep(5 * time.Second)
		return true
	}

	m.log("Target:    " + info.Target)
	m.log("Prev hash: " + info.PreviousHash)

	minerClean := strings.ReplaceAll(minerID, "-", "")
	prefix := []byte(info.PreviousHash + minerClean)

	numWorkers := runtime.NumCPU()
	m.log(fmt.Sprintf("Mining on %d core(s)...", numWorkers))

	found    := make(chan foundBlock, 1)
	stopWork := make(chan struct{})
	var workerHashes atomic.Int64

	for i := 0; i < numWorkers; i++ {
		go m.workerRange(prefix, info.Target, uint64(i), uint64(numWorkers), found, stopWork, &workerHashes)
	}

	t0        := time.Now()
	lastCheck := time.Now()
	lastCount := int64(0)
	lastRateT := time.Now()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			close(stopWork)
			return false

		case fb := <-found:
			close(stopWork)
			elapsed := time.Since(t0)
			m.log(fmt.Sprintf("✔ Block found! Nonce=%d  Hash=%s", fb.nonce, fb.hash))
			m.log("  Submitting...")

			// submit
			payload, _ := json.Marshal(map[string]interface{}{
				"miner_id": minerID,
				"nonce":    fb.nonce,
				"hash":     fb.hash,
			})
			resp, err := http.Post(api+"/api/mining", "application/json", bytes.NewReader(payload))
			if err != nil {
				m.log("Submit error: " + err.Error())
				return true
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode == 200 {
				m.blocksFound.Add(1)
				m.log(fmt.Sprintf("✔ Block accepted! (%.2fs) %s", elapsed.Seconds(), string(body)))
			} else if resp.StatusCode == 409 {
				m.log("✘ Stale — another miner was faster. Restarting...")
				m.log("  Body: " + string(body))
			} else {
				m.log(fmt.Sprintf("✘ Server returned %d", resp.StatusCode))
				m.log("  Body: " + string(body))
			}
			return true

		case <-ticker.C:
			now   := time.Now()
			total := workerHashes.Load()
			delta := total - lastCount
			dt    := now.Sub(lastRateT).Seconds()
			if dt > 0 {
				rate := float64(delta) / dt
				m.hashRate.Store(int64(rate))
				m.totalHashes.Add(delta)
				lastCount = total
				lastRateT = now
			}

			// poll for new block every 20s
			if now.Sub(lastCheck) >= 20*time.Second {
				lastCheck = now
				go func() {
					check, err := m.fetchBlock(api)
					if err == nil && check.PreviousHash != info.PreviousHash {
						m.log("⟳ New block detected — restarting...")
						select {
						case <-stopWork:
						default:
							close(stopWork)
						}
					}
				}()
			}
		}
	}
}

func (m *Miner) startMining(api, minerID string) {
	m.sessionStart = time.Now()
	m.totalHashes.Store(0)
	m.blocksFound.Store(0)
	m.stopChan = make(chan struct{})
	m.mining.Store(true)

	go func() {
		m.log("=" + strings.Repeat("=", 57))
		m.log("Starting miner | Address: " + minerID)
		m.log("API: " + api)
		m.log("=" + strings.Repeat("=", 57))

		for m.mining.Load() {
			m.log("Fetching new block template...")
			if !m.mineBlock(api, minerID) {
				break
			}
		}

		m.mining.Store(false)
	}()
}

func (m *Miner) stopMining() {
	if m.mining.Load() {
		m.mining.Store(false)
		close(m.stopChan)
	}
}

// ── UI ────────────────────────────────────────────────────────────────────────
func (m *Miner) buildUI(a fyne.App) fyne.Window {
	w := a.NewWindow("OmegaCases Miner  v2.0.0")
	w.Resize(fyne.NewSize(740, 680))
	w.SetFixedSize(true)

	// ── Title bar
	icon   := widget.NewLabel("⛏")
	icon.TextStyle = fyne.TextStyle{Bold: true}
	title  := widget.NewLabel("OmegaCases Miner")
	title.TextStyle = fyne.TextStyle{Bold: true}
	sub    := widget.NewLabelWithStyle("SHA-256 Proof-of-Work Client  v2.0.0", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})

	m.statusDot   = canvas.NewText("●", colGrey)
	m.statusDot.TextSize = 14
	m.statusLabel = widget.NewLabel("Offline")

	titleLeft  := container.NewHBox(icon, title, sub)
	titleRight := container.NewHBox(m.statusDot, m.statusLabel)
	titleBar   := container.NewBorder(nil, nil, titleLeft, titleRight)

	// ── Config
	m.apiEntry = widget.NewEntry()
	m.apiEntry.SetText("https://omegacases.com")
	m.apiEntry.SetPlaceHolder("https://omegacases.com")

	m.idEntry = widget.NewEntry()
	m.idEntry.SetPlaceHolder("Paste your miner address here...")

	configForm := widget.NewForm(
		widget.NewFormItem("API URL", m.apiEntry),
		widget.NewFormItem("Miner Address", m.idEntry),
	)
	configCard := widget.NewCard("Configuration", "", configForm)

	// ── Stat cards
	m.hsLabel     = widget.NewLabelWithStyle("0.00 H/s",   fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	m.blocksLabel = widget.NewLabelWithStyle("0",           fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	m.noncesLabel = widget.NewLabelWithStyle("0",           fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	m.uptimeLabel = widget.NewLabelWithStyle("00:00:00",    fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})

	makeStatCard := func(label string, val *widget.Label) fyne.CanvasObject {
		lbl := widget.NewLabelWithStyle(label, fyne.TextAlignCenter, fyne.TextStyle{})
		return widget.NewCard("", "", container.NewVBox(lbl, val))
	}

	statsGrid := container.New(layout.NewGridLayout(4),
		makeStatCard("Hash Rate",    m.hsLabel),
		makeStatCard("Blocks Found", m.blocksLabel),
		makeStatCard("Nonces Tried", m.noncesLabel),
		makeStatCard("Session Time", m.uptimeLabel),
	)

	m.targetLabel = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	m.targetLabel.Wrapping = fyne.TextWrapBreak

	infoForm := widget.NewForm(
		widget.NewFormItem("Current Target", m.targetLabel),
	)
	statsCard := widget.NewCard("Mining Statistics", "", container.NewVBox(statsGrid, infoForm))

	// ── Log
	m.logList = widget.NewList(
		func() int {
			m.logMu.Lock()
			defer m.logMu.Unlock()
			return len(m.logEntries)
		},
		func() fyne.CanvasObject {
			return widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			m.logMu.Lock()
			defer m.logMu.Unlock()
			if id < len(m.logEntries) {
				obj.(*widget.Label).SetText(m.logEntries[id])
			}
		},
	)
	logCard := widget.NewCard("Debug Log", "", container.NewScroll(m.logList))
	logCard.Content.(*container.Scroll).SetMinSize(fyne.NewSize(700, 220))

	// ── Buttons
	var startBtn, stopBtn *widget.Button
	startBtn = widget.NewButton("▶  Start Mining", func() {
		api := strings.TrimRight(m.apiEntry.Text, "/")
		mid := strings.TrimSpace(m.idEntry.Text)
		if api == "" {
			m.log("API URL is required.")
			return
		}
		if mid == "" {
			m.log("Miner address is required.")
			return
		}
		startBtn.Disable()
		stopBtn.Enable()
		m.apiEntry.Disable()
		m.idEntry.Disable()
		m.setStatus("Mining…", colAccent)
		m.startMining(api, mid)
	})
	startBtn.Importance = widget.HighImportance

	stopBtn = widget.NewButton("■  Stop", func() {
		m.stopMining()
		startBtn.Enable()
		stopBtn.Disable()
		m.apiEntry.Enable()
		m.idEntry.Enable()
		m.setStatus("Stopped", colRed)
		m.log("Mining stopped by user.")
	})
	stopBtn.Disable()

	clearBtn := widget.NewButton("Clear Log", func() {
		m.logMu.Lock()
		m.logEntries = []string{}
		m.logMu.Unlock()
		m.logList.Refresh()
	})

	btnRow := container.NewHBox(startBtn, stopBtn, layout.NewSpacer(), clearBtn)

	// ── Ticker for UI refresh
	go func() {
		tick := time.NewTicker(300 * time.Millisecond)
		for range tick.C {
			if m.mining.Load() {
				rate := float64(m.hashRate.Load())
				m.hsLabel.SetText(formatHashRate(rate))
				m.blocksLabel.SetText(fmt.Sprintf("%d", m.blocksFound.Load()))
				total := m.totalHashes.Load()
				m.noncesLabel.SetText(fmt.Sprintf("%s", formatLargeNum(total)))
				elapsed := time.Since(m.sessionStart)
				h := int(elapsed.Hours())
				mn := int(elapsed.Minutes()) % 60
				s := int(elapsed.Seconds()) % 60
				m.uptimeLabel.SetText(fmt.Sprintf("%02d:%02d:%02d", h, mn, s))
			}
		}
	}()

	// ── Layout
	content := container.NewVBox(
		titleBar,
		widget.NewSeparator(),
		configCard,
		statsCard,
		btnRow,
		logCard,
	)

	w.SetContent(container.NewPadded(content))
	w.SetCloseIntercept(func() {
		m.stopMining()
		os.Exit(0)
	})

	_ = theme.DefaultTheme()
	return w
}

func formatLargeNum(n int64) string {
	s := fmt.Sprintf("%d", n)
	out := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func main() {
	a := app.New()
	m := newMiner()
	w := m.buildUI(a)
	w.ShowAndRun()
}
