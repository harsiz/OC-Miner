// Package cpu implements a multi-core CPU minerdevice.Device, for machines
// without a usable GPU/OpenCL driver.
package cpu

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/harsiz/oc-miner/internal/job"
	"github.com/harsiz/oc-miner/internal/minerdevice"
)

const hashesPerCorePerBatch = 200_000

// Miner searches nonce ranges across all available CPU cores.
type Miner struct {
	workers   int
	batchSize uint64
}

// New builds a CPU miner using all available cores.
func New() *Miner {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	return &Miner{
		workers:   workers,
		batchSize: uint64(workers) * hashesPerCorePerBatch,
	}
}

func (m *Miner) Name() string { return fmt.Sprintf("CPU (%d cores)", m.workers) }

func (m *Miner) BatchSize() uint64 { return m.batchSize }

func (m *Miner) Close() {}

// SearchBatch splits [baseNonce, baseNonce+BatchSize()) evenly across all
// worker goroutines and returns the first nonce any of them finds that
// satisfies the job's target.
func (m *Miner) SearchBatch(j *job.Job, baseNonce uint64) (*minerdevice.FoundResult, error) {
	perWorker := m.batchSize / uint64(m.workers)

	var found atomic.Bool
	var result minerdevice.FoundResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for w := 0; w < m.workers; w++ {
		start := baseNonce + uint64(w)*perWorker
		end := start + perWorker
		wg.Add(1)
		go func(start, end uint64) {
			defer wg.Done()
			for n := start; n < end; n++ {
				if n%4096 == 0 && found.Load() {
					return
				}
				h := j.HashNonceFast(n)
				if j.MeetsTarget(h) {
					if found.CompareAndSwap(false, true) {
						mu.Lock()
						result = minerdevice.FoundResult{Nonce: n, HashHex: h}
						mu.Unlock()
					}
					return
				}
			}
		}(start, end)
	}
	wg.Wait()

	if found.Load() {
		return &result, nil
	}
	return nil, nil
}
