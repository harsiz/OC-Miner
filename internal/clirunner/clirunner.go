// Package clirunner is the shared implementation behind the headless CLI
// miners (cmd/oc-miner-cpu, cmd/oc-miner-gpu-cli): flag parsing, wiring a
// minerdevice.Device into the solo/pool mining loop, and printing progress
// to stdout until Ctrl+C.
package clirunner

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/harsiz/oc-miner/internal/engine"
	"github.com/harsiz/oc-miner/internal/minerdevice"
	"github.com/harsiz/oc-miner/internal/poolclient"
	"github.com/harsiz/oc-miner/internal/solo"
)

// Flags are the mining options common to every headless miner.
type Flags struct {
	Mode     string
	API      string
	MinerID  string
	PoolHost string
	PoolPort int
}

// ParseFlags defines and parses the standard -mode/-api/-id/-pool-host/
// -pool-port flags. progName is used in the usage message printed when -id
// is missing.
func ParseFlags(progName string) Flags {
	mode := flag.String("mode", "solo", `mining mode: "solo" or "pool"`)
	api := flag.String("api", "https://omegacases.com", "OmegaCases API base URL (solo mode)")
	minerID := flag.String("id", "", "your OmegaCases user id (solo mode: your miner address; pool mode: the id you joined the pool with)")
	poolHost := flag.String("pool-host", "", "pool host (pool mode)")
	poolPort := flag.Int("pool-port", 3333, "pool port (pool mode)")
	flag.Parse()

	if *minerID == "" {
		fmt.Printf("Usage: %s -mode solo -id <your-user-id> [-api https://omegacases.com]\n", progName)
		fmt.Printf("       %s -mode pool -id <your-user-id> -pool-host <host> [-pool-port 3333]\n", progName)
		os.Exit(1)
	}

	return Flags{
		Mode:     *mode,
		API:      *api,
		MinerID:  *minerID,
		PoolHost: *poolHost,
		PoolPort: *poolPort,
	}
}

// Run wires dev into the solo or pool mining loop per f.Mode and prints
// progress to stdout until Ctrl+C/SIGTERM or the loop reports it stopped.
// dev is closed before Run returns.
func Run(dev minerdevice.Device, f Flags) {
	defer dev.Close()

	msgs := make(chan engine.Msg, 64)
	stop := engine.NewStopFlag()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		stop.Stop()
	}()

	switch f.Mode {
	case "solo":
		go solo.Run(f.API, f.MinerID, dev, msgs, stop)
	case "pool":
		if f.PoolHost == "" {
			fmt.Println("-pool-host is required in pool mode")
			os.Exit(1)
		}
		go poolclient.Run(f.PoolHost, f.PoolPort, f.MinerID, dev, msgs, stop)
	default:
		fmt.Printf("unknown -mode %q, must be \"solo\" or \"pool\"\n", f.Mode)
		os.Exit(1)
	}

	for msg := range msgs {
		switch msg.Kind {
		case engine.MsgLog:
			fmt.Println(msg.Text)
		case engine.MsgStats:
			fmt.Printf("hashrate=%s total=%d blocks=%d shares=%d\n",
				engine.FormatHashrate(msg.Hashrate), msg.TotalHashes, msg.BlocksFound, msg.SharesFound)
		case engine.MsgStatus:
			fmt.Println("status:", msg.Text)
			if msg.Text == "Stopped" || msg.Text == "Error" {
				return
			}
		case engine.MsgAdapterName:
			fmt.Println("device:", msg.Text)
		}
	}
}
