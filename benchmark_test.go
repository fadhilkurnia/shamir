package main

import (
	hcShamir "github.com/hashicorp/vault/shamir"
	"go-shamir/galois"
	"go-shamir/shamir"
	"math/rand"
	"testing"
)

var bytes1k []byte
var bytes10k []byte
var bytes100k []byte

func init() {
	bytes1k = make([]byte, 1_000)
	bytes10k = make([]byte, 10_000)
	bytes100k = make([]byte, 1024*1024)
	rand.Read(bytes1k)
	rand.Read(bytes10k)
	rand.Read(bytes100k)
}

// TODO move this to galois package
func BenchmarkGaloisXorGeneric1K(b *testing.B) {
	bytes1kClone := make([]byte, len(bytes1k))
	copy(bytes1kClone, bytes1k)
	b.SetBytes(int64(len(bytes1k))*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.AddVectorGeneric(bytes1k, bytes1kClone)
	}
}

func BenchmarkGaloisXorSIMD1K(b *testing.B) {
	bytes1kClone := make([]byte, len(bytes1k))
	copy(bytes1kClone, bytes1k)
	b.SetBytes(int64(len(bytes1k))*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.AddVector(bytes1k, bytes1kClone)
	}
}

func BenchmarkGaloisXorGeneric1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes100k))
	copy(bytes100kClone, bytes100k)
	b.SetBytes(int64(len(bytes100k))*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.AddVectorGeneric(bytes100k, bytes100kClone)
	}
}

func BenchmarkGaloisXorSIMD1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes100k))
	copy(bytes100kClone, bytes100k)
	b.SetBytes(int64(len(bytes100k))*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.AddVector(bytes100k, bytes100kClone)
	}
}

func BenchmarkGaloisMulGeneric1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes100k))
	copy(bytes100kClone, bytes100k)
	b.SetBytes(int64(len(bytes100k))*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.MulConstVectorGeneric(10, bytes100kClone)
	}
}

func BenchmarkGaloisMulSIMD1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes100k))
	copy(bytes100kClone, bytes100k)
	b.SetBytes(int64(len(bytes100k))*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		galois.MulConstVector(10, bytes100kClone)
	}
}

func BenchmarkSplitBase1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1k,5,2)
	}
}

func BenchmarkSplitGeneric1K(b *testing.B)  {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes1k, 4, 2)
	}
}

func BenchmarkSplitSIMD1K(b *testing.B)  {
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
		_, _ = hcShamir.Split(bytes10k,4,2)
	}
}

func BenchmarkSplitGeneric10K(b *testing.B)  {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes10k, 4, 2)
	}
}

func BenchmarkSplitSIMD10K(b *testing.B)  {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitBase100K(b *testing.B) {
	b.SetBytes(int64(len(bytes100k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes100k,4,2)
	}
}

func BenchmarkSplitGeneric100K(b *testing.B)  {
	b.SetBytes(int64(len(bytes100k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes100k, 4, 2)
	}
}

func BenchmarkSplitSIMD100K(b *testing.B)  {
	b.SetBytes(int64(len(bytes100k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes100k, 4, 2)
	}
}