//go:build (!amd64 || noasm || appengine || gccgo) && (!arm64 || noasm || appengine || gccgo) && (!ppc64le || noasm || appengine || gccgo)
// +build !amd64 noasm appengine gccgo
// +build !arm64 noasm appengine gccgo
// +build !ppc64le noasm appengine gccgo

package galois

import (
	"encoding/binary"
	"fmt"
)

// AddVector add two vectors a and b elementwise using GF(2^8) arithmetic
// Warning: the result returned is replacing the original vector b
func AddVector(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("a and be should have the same length len(a)=%d, len(b)=%d", len(a), len(b)))
	}

	// use the batch version for bigger vector
	if len(a) >= 256 {
		return AddVectorBatch(a, b)
	}

	for idx, val := range a {
		b[idx] = GalAdd(val, b[idx])
	}

	return b
}

// MulConstVector multiply all elements in vector a with constant c using GF(2^8) arithmetic
// Warning: the result returned is replacing the original vector a
func MulConstVector(c byte, a []byte) []byte {
	for idx, val := range a {
		a[idx] = GalMultiply(val, c)
	}
	return a
}


// AddVectorBatch .
func AddVectorBatch(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("a and be should have the same length len(a)=%d, len(b)=%d", len(a), len(b)))
	}

	origOutPointer := b
	for len(b) >= 32 {
		inS := a[:32]
		v0 := binary.LittleEndian.Uint64(b[:]) ^ binary.LittleEndian.Uint64(inS[:])
		v1 := binary.LittleEndian.Uint64(b[8:]) ^ binary.LittleEndian.Uint64(inS[8:])
		v2 := binary.LittleEndian.Uint64(b[16:]) ^ binary.LittleEndian.Uint64(inS[16:])
		v3 := binary.LittleEndian.Uint64(b[24:]) ^ binary.LittleEndian.Uint64(inS[24:])
		binary.LittleEndian.PutUint64(b[:], v0)
		binary.LittleEndian.PutUint64(b[8:], v1)
		binary.LittleEndian.PutUint64(b[16:], v2)
		binary.LittleEndian.PutUint64(b[24:], v3)
		b = b[32:]
		a = a[32:]
	}
	for n, input := range a {
		b[n] ^= input
	}

	return origOutPointer
}