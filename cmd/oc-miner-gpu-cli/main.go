// Command oc-miner-gpu-cli is a headless (no GUI, no windowing deps) GPU
// miner for OmegaCases, for servers/VPSes with a GPU but no display server.
// Supports both solo mining and pool mining (see internal/protocol for the
// pool wire protocol). For a desktop UI, see cmd/oc-miner-gpu instead.
package main

import (
	"fmt"
	"os"

	"github.com/harsiz/oc-miner/internal/clirunner"
	"github.com/harsiz/oc-miner/internal/gpu"
)

func main() {
	f := clirunner.ParseFlags("oc-miner-gpu-cli")

	dev, err := gpu.New()
	if err != nil {
		fmt.Println("GPU init failed:", err)
		os.Exit(1)
	}

	clirunner.Run(dev, f)
}
