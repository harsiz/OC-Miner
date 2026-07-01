// Command oc-miner-cpu is a cross-platform, headless CPU miner for
// OmegaCases, for machines without a usable GPU/OpenCL driver. Supports both
// solo mining and pool mining (see internal/protocol for the pool wire
// protocol).
package main

import (
	"github.com/harsiz/oc-miner/internal/clirunner"
	"github.com/harsiz/oc-miner/internal/cpu"
)

func main() {
	f := clirunner.ParseFlags("oc-miner-cpu")
	clirunner.Run(cpu.New(), f)
}
