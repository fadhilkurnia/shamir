package main

import (
	hcShamir "github.com/hashicorp/vault/shamir"
	"go-shamir/shamir"
	"math/rand"
	"testing"
)

var bytes1k []byte
var bytes10k []byte
var bytes100k []byte

func init() {
	bytes1k = make([]byte, 32)
	bytes10k = make([]byte, 64)
	bytes100k = make([]byte, 1_000)
	rand.Read(bytes1k)
	rand.Read(bytes10k)
	rand.Read(bytes100k)
}

func BenchmarkSplitBase1K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1k,5,2)
	}
}

func BenchmarkSplitGeneric1K(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes1k, 4, 2)
	}
}

func BenchmarkSplitSIMD1K(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1k, 4, 2)
	}
}

func BenchmarkSplitBase10K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes10k,4,2)
	}
}

func BenchmarkSplitGeneric10K(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes10k, 4, 2)
	}
}

func BenchmarkSplitSIMD10K(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitBase100K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes100k,4,2)
	}
}

func BenchmarkSplitGeneric100K(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes100k, 4, 2)
	}
}

func BenchmarkSplitSIMD100K(b *testing.B)  {
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes100k, 4, 2)
	}
}