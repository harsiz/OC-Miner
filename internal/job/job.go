// Package job implements the OmegaCases mining preimage:
//
//	SHA256(previous_hash_ascii(64B) + id_ascii(32B) + decimal(nonce))
//
// previous_hash is always a 64-char hex digest, which is exactly one SHA-256
// block, so we precompute the midstate after that block on the CPU and let
// the GPU kernel only process block two (id tail + ascii nonce + padding).
package job

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

var sha256IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func rotr(x uint32, n uint32) uint32 { return (x >> n) | (x << (32 - n)) }

// compressBlock runs one SHA-256 compression round, matching FIPS 180-4.
func compressBlock(state [8]uint32, block []byte) [8]uint32 {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}
	for i := 16; i < 64; i++ {
		s0 := rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	for i := 0; i < 64; i++ {
		s1 := rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := h + s1 + ch + sha256K[i] + w[i]
		s0 := rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := s0 + maj
		h, g, f, e = g, f, e, d+temp1
		d, c, b, a = c, b, a, temp1+temp2
	}
	return [8]uint32{
		state[0] + a, state[1] + b, state[2] + c, state[3] + d,
		state[4] + e, state[5] + f, state[6] + g, state[7] + h,
	}
}

// Job is a single unit of mining work (one block template).
type Job struct {
	PreviousHash string
	IDClean      string
	TargetHex    string
	Midstate     [8]uint32
	PrefixTail   [32]byte
	TargetBytes  [32]byte
}

// New builds a Job from a previous_hash (64 hex chars) and a user/pool id
// (a UUID, with or without dashes) plus a target hex string.
func New(previousHash, id, targetHex string) (*Job, error) {
	idClean := strings.ReplaceAll(id, "-", "")
	if len(previousHash) != 64 {
		return nil, fmt.Errorf("previous_hash must be 64 hex chars, got %d", len(previousHash))
	}
	if len(idClean) != 32 {
		return nil, fmt.Errorf("id must be 32 hex chars once dashes are stripped, got %d", len(idClean))
	}

	state := compressBlock(sha256IV, []byte(previousHash))

	var prefixTail [32]byte
	copy(prefixTail[:], idClean)

	return &Job{
		PreviousHash: previousHash,
		IDClean:      idClean,
		TargetHex:    targetHex,
		Midstate:     state,
		PrefixTail:   prefixTail,
		TargetBytes:  hexTo32(targetHex),
	}, nil
}

// HashNonce computes the reference (CPU) hash for a candidate nonce; used to
// verify GPU results before submitting them anywhere.
func (j *Job) HashNonce(nonce uint64) string {
	h := sha256.New()
	h.Write([]byte(j.PreviousHash))
	h.Write([]byte(j.IDClean))
	h.Write([]byte(strconv.FormatUint(nonce, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// HashNonceFast computes the same hash as HashNonce but reuses the
// precomputed midstate, skipping re-compression of the fixed 64-byte
// previous_hash block. This is what CPU mining uses for its hot loop; the
// two must always agree (see job_test.go), and callers that submit a result
// anywhere should still double-check it against HashNonce first as a safety
// net against any divergence between the two implementations.
func (j *Job) HashNonceFast(nonce uint64) string {
	digits := strconv.FormatUint(nonce, 10)
	var block [64]byte
	copy(block[:32], j.PrefixTail[:])
	copy(block[32:], digits)
	msgLen := 32 + len(digits)
	block[msgLen] = 0x80
	totalBits := uint64(96+len(digits)) * 8
	binary.BigEndian.PutUint64(block[56:64], totalBits)

	final := compressBlock(j.Midstate, block[:])
	var out [32]byte
	for i, w := range final {
		binary.BigEndian.PutUint32(out[i*4:], w)
	}
	return hex.EncodeToString(out[:])
}

// MeetsTarget reports whether hashHex satisfies this job's target, using the
// same lexicographic hex-string comparison the server performs.
func (j *Job) MeetsTarget(hashHex string) bool {
	return hashHex < j.TargetHex
}

func hexTo32(s string) [32]byte {
	padded := s
	for len(padded) < 64 {
		padded = "0" + padded
	}
	if len(padded) > 64 {
		padded = padded[len(padded)-64:]
	}
	var out [32]byte
	if b, err := hex.DecodeString(padded); err == nil {
		copy(out[:], b)
	}
	return out
}
