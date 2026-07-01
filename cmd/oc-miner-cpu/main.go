// Command oc-miner-cpu is a cross-platform, command-line-only CPU miner for
// OmegaCases, for machines without a usable GPU/OpenCL driver. Supports both
// solo mining and pool mining (see internal/protocol for the pool wire
// protocol).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/harsiz/oc-miner/internal/cpu"
	"github.com/harsiz/oc-miner/internal/engine"
	"github.com/harsiz/oc-miner/internal/poolclient"
	"github.com/harsiz/oc-miner/internal/solo"
)

func main() {
	mode := flag.String("mode", "solo", `mining mode: "solo" or "pool"`)
	api := flag.String("api", "https://omegacases.com", "OmegaCases API base URL (solo mode)")
	minerID := flag.String("id", "", "your OmegaCases user id (solo mode: your miner address; pool mode: the id you joined the pool with)")
	poolHost := flag.String("pool-host", "", "pool host (pool mode)")
	poolPort := flag.Int("pool-port", 3333, "pool port (pool mode)")
	flag.Parse()

	if *minerID == "" {
		fmt.Println("Usage: oc-miner-cpu -mode solo -id <your-user-id> [-api https://omegacases.com]")
		fmt.Println("       oc-miner-cpu -mode pool -id <your-user-id> -pool-host <host> [-pool-port 3333]")
		os.Exit(1)
	}

	dev := cpu.New()
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

	switch *mode {
	case "solo":
		go solo.Run(*api, *minerID, dev, msgs, stop)
	case "pool":
		if *poolHost == "" {
			fmt.Println("-pool-host is required in pool mode")
			os.Exit(1)
		}
		go poolclient.Run(*poolHost, *poolPort, *minerID, dev, msgs, stop)
	default:
		fmt.Printf("unknown -mode %q, must be \"solo\" or \"pool\"\n", *mode)
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
