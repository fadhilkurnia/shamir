//go:build (!amd64 || noasm || appengine || gccgo) && (!arm64 || noasm || appengine || gccgo) && (!ppc64le || noasm || appengine || gccgo)
// +build !amd64 noasm appengine gccgo
// +build !arm64 noasm appengine gccgo
// +build !ppc64le noasm appengine gccgo

package galois

// AddVector add two vectors a and b elementwise using GF(2^8) arithmetic
// Warning: the result returned is replacing the original vector b
func AddVector(a, b []byte) []byte {
	return AddVectorGeneric(a, b)
}

// MulConstVector multiply all elements in vector a with constant c using GF(2^8) arithmetic
// Warning: the result returned is replacing the original vector a
func MulConstVector(c byte, a []byte) []byte {
	return MulConstVectorGeneric(c, a)
}
