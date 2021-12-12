//go:build !noasm && !appengine && !gccgo
// +build !noasm,!appengine,!gccgo

// Copyright 2015, Klaus Post, see LICENSE for details.

package galois

import "github.com/klauspost/cpuid/v2"

var useSSSE3 = false
var useSSE2 = false
var useAVX2 = false
var useAVX512 = false

func init() {
	useSSSE3 = cpuid.CPU.Supports(cpuid.SSSE3)
	useSSE2 = cpuid.CPU.Supports(cpuid.SSE2)
	useAVX2 = cpuid.CPU.Supports(cpuid.AVX2)
	useAVX512 = cpuid.CPU.Supports(cpuid.AVX512F, cpuid.AVX512BW)
}

//go:noescape
func galMulSSSE3(low, high, in, out []byte)

//go:noescape
func galMulSSSE3Xor(low, high, in, out []byte)

//go:noescape
func galMulAVX2Xor(low, high, in, out []byte)

//go:noescape
func galMulAVX2(low, high, in, out []byte)

//go:noescape
func sSE2XorSlice(in, out []byte)

//go:noescape
func galMulAVX2Xor_64(low, high, in, out []byte)

//go:noescape
func galMulAVX2_64(low, high, in, out []byte)

//go:noescape
func sSE2XorSlice_64(in, out []byte)

// This is what the assembler routines do in blocks of 16 bytes:
/*
func galMulSSSE3(low, high, in, out []byte) {
	for n, input := range in {
		l := input & 0xf
		h := input >> 4
		out[n] = low[l] ^ high[h]
	}
}

func galMulSSSE3Xor(low, high, in, out []byte) {
	for n, input := range in {
		l := input & 0xf
		h := input >> 4
		out[n] ^= low[l] ^ high[h]
	}
}
*/

// bigSwitchover is the size where 64 bytes are processed per loop.
const bigSwitchover = 128

func galMulSlice(c byte, in, out []byte) []byte {
	origOutPointer := out

	if c == 1 {
		copy(out, in)
		return origOutPointer
	}
	if useAVX2 {
		if len(in) >= bigSwitchover {
			galMulAVX2_64(mulTableLow[c][:], mulTableHigh[c][:], in, out)
			done := (len(in) >> 6) << 6
			in = in[done:]
			out = out[done:]
		}
		if len(in) > 32 {
			galMulAVX2(mulTableLow[c][:], mulTableHigh[c][:], in, out)
			done := (len(in) >> 5) << 5
			in = in[done:]
			out = out[done:]
		}
	} else if useSSSE3 {
		galMulSSSE3(mulTableLow[c][:], mulTableHigh[c][:], in, out)
		done := (len(in) >> 4) << 4
		if done < len(out) {
			in = in[done:]
			out = out[done:]
		}
	}
	out = out[:len(in)]
	mt := mulTable[c][:256]
	for i := range in {
		out[i] = mt[in[i]]
	}

	return origOutPointer
}

// simple slice xor
func sliceXor(in, out []byte) []byte {
	origOutPointer := out

	if useSSE2 {
		if len(in) >= bigSwitchover {
			sSE2XorSlice_64(in, out)
			done := (len(in) >> 6) << 6
			in = in[done:]
			out = out[done:]
		}
		if len(in) >= 16 {
			sSE2XorSlice(in, out)
			done := (len(in) >> 4) << 4
			in = in[done:]
			out = out[done:]
		}
	}
	out = out[:len(in)]
	for i := range in {
		out[i] ^= in[i]
	}

	return origOutPointer
}