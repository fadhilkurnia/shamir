package shamir

import (
	"github.com/fadhilkurnia/shamir/csprng"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TODO: implement this
// func BenchmarkMakePolynomials()
// func BenchmarkEvaluatePolynomialsAt()

var bytes100 []byte
var bytes1k []byte
var bytes10k []byte
var bytes1M []byte

func init() {
	bytes100 = make([]byte, 50)
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

func BenchmarkSplit100(b *testing.B) {
	b.SetBytes(int64(len(bytes100)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Split(bytes100, 4, 2)
	}
}

func BenchmarkParallelSplit100(b *testing.B) {
	numThreads := 4
	numRequest := 1_000_000
	reqSize := 50

	buff := make([]byte, reqSize)
	rand.Read(buff)
	input := make(chan []byte, 1_000)
	output := make(chan [][]byte, 1_000)

	for i := 0; i < numThreads; i++ {
		go func() {
			for in := range input {
				res, _ := Split(in, 4, 2)
				output <- res
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < numRequest; i++ {
			in := make([]byte, 50)
			copy(in, buff)
			input <- in
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRequest; i++ {
			<- output
		}
	}()
	wg.Wait()

	dur := time.Since(start)
	b.Log("duration ", dur)
	b.Log("capacity ", float64(numRequest)/dur.Seconds(), "req/s")
}

func BenchmarkSplit10KB(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitWithOldRandomizer(b *testing.B) {
	r := csprng.NewCSPRNG()
	b.SetBytes(int64(len(bytes1M)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SplitWithRandomizerOld(bytes1M, 4, 2, r)
	}
}

func BenchmarkSplitWithRandomizer(b *testing.B) {
	r := csprng.NewCSPRNG()
	b.SetBytes(int64(len(bytes1M)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SplitWithRandomizer(bytes1M, 4, 2, r)
	}
}