package job

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// hashNonceViaMidstate replicates exactly what the GPU kernel does: build
// block two from the fixed 32-byte tail plus the ascii nonce plus padding,
// then run one more compression round on top of the precomputed midstate.
// It must always agree with HashNonce (the reference, from-scratch hash).
func (j *Job) hashNonceViaMidstate(nonce uint64) string {
	digits := strconv.FormatUint(nonce, 10)
	var block [64]byte
	copy(block[:32], j.PrefixTail[:])
	copy(block[32:], digits)
	msgLen := 32 + len(digits)
	block[msgLen] = 0x80
	totalBits := uint64(96+len(digits)) * 8
	binary.BigEndian.PutUint64(block[56:64], totalBits)

	final := compressBlock(j.Midstate, block[:])
	out := make([]byte, 32)
	for i, w := range final {
		binary.BigEndian.PutUint32(out[i*4:], w)
	}
	const hexdigits = "0123456789abcdef"
	hexOut := make([]byte, 64)
	for i, b := range out {
		hexOut[i*2] = hexdigits[b>>4]
		hexOut[i*2+1] = hexdigits[b&0xf]
	}
	return string(hexOut)
}

func TestMidstateMatchesFullHash(t *testing.T) {
	j, err := New(
		strings.Repeat("0", 64),
		"11111111-1111-1111-1111-111111111111",
		strings.Repeat("f", 64),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	j2, err := New(
		strings.Repeat("a1b2c3d4e5f60718", 4),
		"deadbeefdeadbeefdeadbeefdeadbeef",
		"00000f"+strings.Repeat("f", 58),
	)
	if err != nil {
		t.Fatalf("New j2: %v", err)
	}

	for _, job := range []*Job{j, j2} {
		for _, nonce := range []uint64{0, 1, 9, 10, 99, 100, 123456789, 1 << 32, 1<<32 + 42, 18446744073709551615} {
			got := job.hashNonceViaMidstate(nonce)
			want := job.HashNonce(nonce)
			if got != want {
				t.Errorf("nonce=%d: midstate hash = %s, want %s", nonce, got, want)
			}
		}
	}
}
