//go:build !noasm && !appengine && !gccgo
// +build !noasm,!appengine,!gccgo

// Copyright 2015, Klaus Post, see LICENSE for details.
// Copyright 2017, Minio, Inc.
package galois

//go:noescape
func galMulNEON(low, high, in, out []byte)

//go:noescape
func galMulXorNEON(low, high, in, out []byte)

//go:noescape
func galXorNEON(in, out []byte)

func MulConstVector(c byte, in []byte) []byte {
	out := make([]byte, len(in))

	if c == 1 {
		copy(out, in)
		return out
	}
	var done int
	galMulNEON(mulTableLow[c][:], mulTableHigh[c][:], in, out)
	done = (len(in) >> 5) << 5

	remain := len(in) - done
	if remain > 0 {
		mt := mulTable[c][:256]
		for i := done; i < len(in); i++ {
			out[i] = mt[in[i]]
		}
	}

	return out
}

// simple slice xor
func AddVector(in, out []byte) []byte {
	origOutPointer := out

	galXorNEON(in, out)
	done := (len(in) >> 5) << 5

	remain := len(in) - done
	if remain > 0 {
		for i := done; i < len(in); i++ {
			out[i] ^= in[i]
		}
	}

	return origOutPointer
}