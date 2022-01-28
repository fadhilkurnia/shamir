package main

import (
	"github.com/fadhilkurnia/shamir/galois"
	"github.com/fadhilkurnia/shamir/krawczyk"
	"github.com/fadhilkurnia/shamir/shamir"
	hcShamir "github.com/hashicorp/vault/shamir"
	"math/rand"
	"testing"
	"time"
)

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

// TODO move this to galois package
func BenchmarkGaloisXorBase1K(b *testing.B) {
	va := make([]byte, 1_000)
	vb := make([]byte, 1_000)
	rand.Read(va)
	rand.Read(vb)
	b.SetBytes(int64(len(va)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1_000; j++ {
			vb[j] = galois.GalAdd(va[j], vb[j])
		}
	}
}

func BenchmarkGaloisXorGeneric1K(b *testing.B) {
	bytes1kClone := make([]byte, len(bytes1k))
	copy(bytes1kClone, bytes1k)
	b.SetBytes(int64(len(bytes1k)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes1kClone = galois.AddVectorGeneric(bytes1k, bytes1kClone)
	}
}

func BenchmarkGaloisXorSIMD1K(b *testing.B) {
	bytes1kClone := make([]byte, len(bytes1k))
	copy(bytes1kClone, bytes1k)
	b.SetBytes(int64(len(bytes1k)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes1kClone = galois.AddVector(bytes1k, bytes1kClone)
	}
}

func BenchmarkGaloisXorBase1M(b *testing.B) {
	n := 1024 * 1024
	va := make([]byte, n)
	vb := make([]byte, n)
	rand.Read(va)
	rand.Read(vb)
	b.SetBytes(int64(n) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			vb[j] = galois.GalAdd(va[j], vb[j])
		}
	}
}

func BenchmarkGaloisXorGeneric1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes100kClone = galois.AddVectorGeneric(bytes1M, bytes100kClone)
	}
}

func BenchmarkGaloisXorSIMD1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes100kClone = galois.AddVector(bytes1M, bytes100kClone)
	}
}

func BenchmarkGaloisMulGeneric1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.MulConstVectorGeneric(10, bytes100kClone)
	}
}

func BenchmarkGaloisMulSIMD1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.MulConstVector(10, bytes100kClone)
	}
}

func BenchmarkSplitSIMD100(b *testing.B) {
	b.SetBytes(int64(len(bytes100)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var results [][]byte
		results, _ = shamir.Split(bytes100, 4, 2)
		if len(results) == 0 {
			break
		}
	}
}

func BenchmarkSplitSIMD100NoDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitSIMD100w5msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitSIMD100w10msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitBase1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1k, 5, 2)
	}
}

func BenchmarkSplitGeneric1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes1k, 4, 2)
	}
}

func BenchmarkSplitSIMD1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1k, 4, 2)
	}
}

func BenchmarkSplitBase10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitGeneric10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes10k, 4, 2)
	}
}

func BenchmarkSplitSIMD10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitBase1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1M, 4, 2)
	}
}

func BenchmarkSplitGeneric1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes1M, 4, 2)
	}
}

func BenchmarkSplitSIMD1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1M, 4, 2)
	}
}

func BenchmarkSplitKrawczyk100(b *testing.B) {
	b.SetBytes(int64(len(bytes100)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var results [][]byte
		results, _ = krawczyk.Split(bytes100, 4, 2)
		if len(results) == 0 {
			break
		}
	}
}

func BenchmarkSplitKrawczyk100NoDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = krawczyk.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitKrawczyk100w5msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitKrawczyk100w10msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitKrawczyk1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = krawczyk.Split(bytes1k, 4, 2)
	}
}

func BenchmarkSplitKrawczyk10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = krawczyk.Split(bytes10k, 4, 2)
	}
}
