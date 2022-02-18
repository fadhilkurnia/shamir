package randomizer

import (
	crand "crypto/rand"
	"math/rand"
	"testing"
)

func BenchmarkRandom1M(b *testing.B) {
	buff := make([]byte, 1_000_000)
	r := NewRandomizer()
	b.SetBytes(int64(len(buff)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.Read(buff)
	}
}

func BenchmarkRandomGo1M(b *testing.B) {
	buff := make([]byte, 1_000_000)
	b.SetBytes(int64(len(buff)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rand.Read(buff)
	}
}

func BenchmarkRandomGoCrypto1M(b *testing.B) {
	buff := make([]byte, 1_000_000)
	b.SetBytes(int64(len(buff)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = crand.Read(buff)
	}
}