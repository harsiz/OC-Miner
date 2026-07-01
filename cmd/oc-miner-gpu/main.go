// Command oc-miner-gpu is a cross-platform GPU miner for OmegaCases with a
// desktop UI, supporting both solo mining and pool mining.
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/harsiz/oc-miner/internal/engine"
	"github.com/harsiz/oc-miner/internal/gpu"
	"github.com/harsiz/oc-miner/internal/poolclient"
	"github.com/harsiz/oc-miner/internal/solo"
)

const maxLogLines = 500

type minerUI struct {
	win fyne.Window

	modeSelect *widget.Select

	apiEntry     *widget.Entry
	minerIDEntry *widget.Entry

	poolHostEntry   *widget.Entry
	poolPortEntry   *widget.Entry
	poolUserIDEntry *widget.Entry
	soloConfig      *fyne.Container
	poolConfig      *fyne.Container

	startBtn *widget.Button
	stopBtn  *widget.Button

	statusDot   *widget.Icon
	statusLabel *widget.Label
	adapterLabel *widget.Label

	hashrateLabel *widget.Label
	foundLabel    *widget.Label
	foundValue    *widget.Label
	noncesLabel   *widget.Label
	uptimeLabel   *widget.Label

	logText   *widget.Label
	logScroll *container.Scroll
	logLines  []string

	stop         *engine.StopFlag
	mining       bool
	sessionStart time.Time
}

func main() {
	a := app.New()
	w := a.NewWindow("OmegaCases GPU Miner")
	w.Resize(fyne.NewSize(760, 720))

	ui := &minerUI{win: w}
	w.SetContent(ui.build())
	w.SetOnClosed(func() {
		if ui.stop != nil {
			ui.stop.Stop()
		}
	})

	go ui.tickUptime()

	w.ShowAndRun()
}

func (u *minerUI) build() fyne.CanvasObject {
	title := widget.NewLabelWithStyle("⛏ OmegaCases GPU Miner", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	u.statusDot = widget.NewIcon(theme.MediaStopIcon())
	u.statusLabel = widget.NewLabel("Idle")
	statusBox := container.NewHBox(u.statusDot, u.statusLabel)
	titleBar := container.NewBorder(nil, nil, title, statusBox)

	u.adapterLabel = widget.NewLabel("GPU: —")

	u.modeSelect = widget.NewSelect([]string{"Solo Mining", "Pool Mining"}, u.onModeChanged)

	u.apiEntry = widget.NewEntry()
	u.apiEntry.SetText("https://omegacases.com")
	u.minerIDEntry = widget.NewEntry()
	u.minerIDEntry.SetPlaceHolder("Paste your miner address (user id) here...")
	u.soloConfig = container.New(layout.NewFormLayout(),
		widget.NewLabel("API URL"), u.apiEntry,
		widget.NewLabel("Miner Address"), u.minerIDEntry,
	)

	u.poolHostEntry = widget.NewEntry()
	u.poolHostEntry.SetPlaceHolder("pool host, e.g. 203.0.113.10")
	u.poolPortEntry = widget.NewEntry()
	u.poolPortEntry.SetText("3333")
	u.poolUserIDEntry = widget.NewEntry()
	u.poolUserIDEntry.SetPlaceHolder("Your OmegaCases user id")
	u.poolConfig = container.New(layout.NewFormLayout(),
		widget.NewLabel("Pool Host"), u.poolHostEntry,
		widget.NewLabel("Pool Port"), u.poolPortEntry,
		widget.NewLabel("Your User ID"), u.poolUserIDEntry,
	)
	u.poolConfig.Hide()
	u.modeSelect.SetSelected("Solo Mining")

	configCard := widget.NewCard("Configuration", "", container.NewVBox(u.modeSelect, u.soloConfig, u.poolConfig))

	u.startBtn = widget.NewButtonWithIcon("Start Mining", theme.MediaPlayIcon(), u.start)
	u.startBtn.Importance = widget.HighImportance
	u.stopBtn = widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), u.stopMining)
	u.stopBtn.Disable()
	clearBtn := widget.NewButton("Clear Log", func() {
		u.logLines = nil
		u.logText.SetText("")
	})
	btnRow := container.NewHBox(u.startBtn, u.stopBtn, layout.NewSpacer(), clearBtn)

	u.hashrateLabel = widget.NewLabelWithStyle("0.00 H/s", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	u.foundLabel = widget.NewLabel("Blocks Found")
	u.foundValue = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	u.noncesLabel = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})
	u.uptimeLabel = widget.NewLabelWithStyle("00:00:00", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})

	statCard := func(label string, value fyne.CanvasObject) fyne.CanvasObject {
		return widget.NewCard("", "", container.NewVBox(widget.NewLabel(label), value))
	}
	statsGrid := container.NewGridWithColumns(4,
		statCard("Hash Rate", u.hashrateLabel),
		statCard("Blocks / Shares", container.NewVBox(u.foundLabel, u.foundValue)),
		statCard("Nonces Tried", u.noncesLabel),
		statCard("Session Time", u.uptimeLabel),
	)

	u.logText = widget.NewLabel("")
	u.logText.Wrapping = fyne.TextWrapOff
	u.logScroll = container.NewVScroll(u.logText)
	u.logScroll.SetMinSize(fyne.NewSize(700, 260))
	logCard := widget.NewCard("Debug Log", "", u.logScroll)

	return container.NewPadded(container.NewVBox(
		titleBar,
		u.adapterLabel,
		widget.NewSeparator(),
		configCard,
		btnRow,
		statsGrid,
		logCard,
	))
}

func (u *minerUI) onModeChanged(mode string) {
	if mode == "Solo Mining" {
		u.soloConfig.Show()
		u.poolConfig.Hide()
	} else {
		u.soloConfig.Hide()
		u.poolConfig.Show()
	}
}

func (u *minerUI) appendLog(s string) {
	ts := time.Now().Format("15:04:05")
	u.logLines = append(u.logLines, fmt.Sprintf("[%s] %s", ts, s))
	if len(u.logLines) > maxLogLines {
		u.logLines = u.logLines[len(u.logLines)-maxLogLines:]
	}
	u.logText.SetText(strings.Join(u.logLines, "\n"))
	u.logScroll.ScrollToBottom()
}

func (u *minerUI) setInputsEnabled(enabled bool) {
	entries := []*widget.Entry{u.apiEntry, u.minerIDEntry, u.poolHostEntry, u.poolPortEntry, u.poolUserIDEntry}
	for _, e := range entries {
		if enabled {
			e.Enable()
		} else {
			e.Disable()
		}
	}
	if enabled {
		u.modeSelect.Enable()
	} else {
		u.modeSelect.Disable()
	}
}

func (u *minerUI) start() {
	msgs := make(chan engine.Msg, 64)
	stop := engine.NewStopFlag()

	dev, err := gpu.New()
	if err != nil {
		u.appendLog(fmt.Sprintf("GPU init failed: %v", err))
		return
	}

	switch u.modeSelect.Selected {
	case "Solo Mining":
		api := strings.TrimSpace(u.apiEntry.Text)
		id := strings.TrimSpace(u.minerIDEntry.Text)
		if api == "" || id == "" {
			dev.Close()
			u.appendLog("API URL and miner address are required.")
			return
		}
		go func() {
			defer dev.Close()
			solo.Run(api, id, dev, msgs, stop)
		}()
	case "Pool Mining":
		host := strings.TrimSpace(u.poolHostEntry.Text)
		port, err := strconv.Atoi(strings.TrimSpace(u.poolPortEntry.Text))
		if err != nil {
			port = 3333
		}
		id := strings.TrimSpace(u.poolUserIDEntry.Text)
		if host == "" || id == "" {
			dev.Close()
			u.appendLog("Pool host and your user id are required.")
			return
		}
		go func() {
			defer dev.Close()
			poolclient.Run(host, port, id, dev, msgs, stop)
		}()
	}

	u.stop = stop
	u.mining = true
	u.sessionStart = time.Now()
	u.startBtn.Disable()
	u.stopBtn.Enable()
	u.setInputsEnabled(false)
	u.statusLabel.SetText("Starting...")

	go u.drain(msgs)
}

func (u *minerUI) stopMining() {
	if u.stop != nil {
		u.stop.Stop()
	}
	u.mining = false
	u.startBtn.Enable()
	u.stopBtn.Disable()
	u.setInputsEnabled(true)
	u.statusLabel.SetText("Stopped")
	u.appendLog("Mining stopped by user.")
}

func (u *minerUI) drain(msgs <-chan engine.Msg) {
	for msg := range msgs {
		m := msg
		fyne.Do(func() {
			switch m.Kind {
			case engine.MsgLog:
				u.appendLog(m.Text)
			case engine.MsgStats:
				u.hashrateLabel.SetText(engine.FormatHashrate(m.Hashrate))
				u.noncesLabel.SetText(formatLargeNum(m.TotalHashes))
				if m.BlocksFound > 0 || u.modeSelect.Selected == "Solo Mining" {
					u.foundLabel.SetText("Blocks Found")
					u.foundValue.SetText(fmt.Sprintf("%d", m.BlocksFound))
				} else {
					u.foundLabel.SetText("Shares Found")
					u.foundValue.SetText(fmt.Sprintf("%d", m.SharesFound))
				}
			case engine.MsgStatus:
				u.statusLabel.SetText(m.Text)
				if m.Text == "Stopped" || m.Text == "Error" {
					u.mining = false
					u.startBtn.Enable()
					u.stopBtn.Disable()
					u.setInputsEnabled(true)
				}
			case engine.MsgAdapterName:
				u.adapterLabel.SetText("GPU: " + m.Text)
			}
		})
	}
}

func (u *minerUI) tickUptime() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !u.mining {
			continue
		}
		elapsed := time.Since(u.sessionStart)
		h := int(elapsed.Hours())
		m := int(elapsed.Minutes()) % 60
		s := int(elapsed.Seconds()) % 60
		fyne.Do(func() {
			u.uptimeLabel.SetText(fmt.Sprintf("%02d:%02d:%02d", h, m, s))
		})
	}
}

func formatLargeNum(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var out strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(c)
	}
	return out.String()
}
