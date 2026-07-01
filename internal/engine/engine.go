// Package engine holds types shared between the solo and pool mining loops
// and the UI that drives them.
package engine

import (
	"fmt"
	"sync/atomic"
)

type MsgKind int

const (
	MsgLog MsgKind = iota
	MsgStats
	MsgStatus
	MsgAdapterName
)

// Msg is sent from a mining goroutine to the UI over a channel.
type Msg struct {
	Kind         MsgKind
	Text         string // Log, Status, AdapterName
	Hashrate     float64
	TotalHashes  uint64
	BlocksFound  uint64
	SharesFound  uint64
}

func FormatHashrate(hs float64) string {
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

// StopFlag is a simple cooperative-cancellation signal shared between the UI
// goroutine and a mining goroutine.
type StopFlag struct {
	stopped atomic.Bool
}

func NewStopFlag() *StopFlag       { return &StopFlag{} }
func (s *StopFlag) Stop()          { s.stopped.Store(true) }
func (s *StopFlag) IsStopped() bool { return s.stopped.Load() }
