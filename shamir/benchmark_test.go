package shamir

import (
	"github.com/fadhilkurnia/shamir/csprng"
	"math/rand"
	"testing"
)

// TODO: implement this
// func BenchmarkMakePolynomials()
// func BenchmarkEvaluatePolynomialsAt()

var bytes100 []byte
var bytes1k []byte
var bytes10k []byte
var bytes1M []byte

func init() {
	bytes100 = make([]byte, 100)
	bytes1k = make([]byte, 1_000)
	bytes10k = make([]byte, 10_000)
	bytes1M = make([]byte, 1024*1024)
	rand.Read(bytes100)
	rand.Read(bytes1k)
	rand.Read(bytes10k)
	rand.Read(bytes1M)
}

func BenchmarkSplit(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Split(bytes1M, 4, 2)
	}
}

func BenchmarkSplitWithRandomizer(b *testing.B) {
	r := csprng.NewCSPRNG()
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SplitWithRandomizer(bytes1M, 4, 2, r)
	}
}