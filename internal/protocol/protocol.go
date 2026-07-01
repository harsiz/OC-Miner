// Package protocol defines the OC-Miner Pool Protocol v1.
//
// OmegaCases does not specify a miner<->pool wire protocol (see
// /developer/docs/mining-pools — pool operators are free to build anything of
// their own). This is the protocol this miner speaks, and cmd/oc-pool-server
// is a reference pool implementation that speaks it too.
//
// Wire format: newline-delimited JSON, one message per line, either direction.
// Note: OmegaCases's own liveness prober connects separately and sends the
// raw bytes "PING", expecting "PONG" back - that check is unrelated to this
// JSON protocol and is handled by the pool server before it decides whether
// to speak JSON on a given connection.
package protocol

// ClientMsg is a message sent from miner to pool.
type ClientMsg struct {
	Type    string `json:"type"` // "hello" | "share" | "pong"
	UserID  string `json:"user_id,omitempty"`
	Nonce   uint64 `json:"nonce,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

// ServerMsg is a message sent from pool to miner.
type ServerMsg struct {
	Type         string `json:"type"` // "job" | "share_result" | "ping"
	PoolID       string `json:"pool_id,omitempty"`
	PreviousHash string `json:"previous_hash,omitempty"`
	Target       string `json:"target,omitempty"`
	Accepted     bool   `json:"accepted,omitempty"`
	Message      string `json:"message,omitempty"`
}
