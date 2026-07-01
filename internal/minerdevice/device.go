// Package minerdevice defines the common interface solo and pool mining
// loops drive, so the same loop code works against either the GPU miner
// (internal/gpu) or the CPU miner (internal/cpu).
package minerdevice

import "github.com/harsiz/oc-miner/internal/job"

// FoundResult is a nonce whose hash satisfied a job's target.
type FoundResult struct {
	Nonce   uint64
	HashHex string
}

// Device searches nonce ranges for a job in batches.
type Device interface {
	// Name describes the device for logging, e.g. "gfx90c (OpenCL)" or "CPU (8 cores)".
	Name() string
	// BatchSize is the number of nonces searched per SearchBatch call.
	BatchSize() uint64
	// SearchBatch searches BatchSize() nonces starting at baseNonce.
	SearchBatch(j *job.Job, baseNonce uint64) (*FoundResult, error)
	// Close releases any resources held by the device.
	Close()
}
