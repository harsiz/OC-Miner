package job

import (
	"strings"
	"testing"
)

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
			got := job.HashNonceFast(nonce)
			want := job.HashNonce(nonce)
			if got != want {
				t.Errorf("nonce=%d: HashNonceFast = %s, want %s", nonce, got, want)
			}
		}
	}
}
