package galois

import (
	"math/rand"
	"testing"
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

func BenchmarkGaloisXorBase1K(b *testing.B) {
	va := make([]byte, 1_000)
	vb := make([]byte, 1_000)
	rand.Read(va)
	rand.Read(vb)
	b.SetBytes(int64(len(va)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1_000; j++ {
			vb[j] = GalAdd(va[j], vb[j])
		}
	}
}

func BenchmarkGaloisXorGeneric1K(b *testing.B) {
	bytes1kClone := make([]byte, len(bytes1k))
	copy(bytes1kClone, bytes1k)
	b.SetBytes(int64(len(bytes1k)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes1kClone = AddVectorGeneric(bytes1k, bytes1kClone)
	}
}

func BenchmarkGaloisXorSIMD1K(b *testing.B) {
	bytes1kClone := make([]byte, len(bytes1k))
	copy(bytes1kClone, bytes1k)
	b.SetBytes(int64(len(bytes1k)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes1kClone = AddVector(bytes1k, bytes1kClone)
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
			vb[j] = GalAdd(va[j], vb[j])
		}
	}
}

func BenchmarkGaloisXorGeneric1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes100kClone = AddVectorGeneric(bytes1M, bytes100kClone)
	}
}

func BenchmarkGaloisXorSIMD1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bytes100kClone = AddVector(bytes1M, bytes100kClone)
	}
}

func BenchmarkGaloisMulGeneric1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MulConstVectorGeneric(10, bytes100kClone)
	}
}

func BenchmarkGaloisMulSIMD1M(b *testing.B) {
	bytes100kClone := make([]byte, len(bytes1M))
	copy(bytes100kClone, bytes1M)
	b.SetBytes(int64(len(bytes1M)) * 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MulConstVector(10, bytes100kClone)
	}
}
