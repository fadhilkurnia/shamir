package shamir

import (
	"crypto/subtle"
	"github.com/fadhilkurnia/shamir/csprng"
	gf "github.com/fadhilkurnia/shamir/galois"
	"github.com/fadhilkurnia/shamir/utils"
	"math/rand"
)

var polynomialBufferPool *utils.BytesBufferPool

func init() {
	polynomialBufferPool = utils.NewBytesBufferPool(0)
}

func makePolynomialsWithBuff(intercepts []uint8, degree int, buffer []uint8) ([]uint8, error) {
	N := len(intercepts)

	// assign random coefficients for all the N polynomials
	_, _ = rand.Read(buffer)

	for p := 0; p < N; p++ {
		s := (degree+1)*p
		e := s + degree+1

		// polynomials[p][0] is the intercept
		// polynomials[p][1:] is the other coefficients that we fill with random
		polynomialP := buffer[s:e]
		polynomialP[0] = intercepts[p]
	}

	return buffer, nil
}

func makePolynomialsWithBuffAndRandomizer(intercepts []uint8, degree int, buffer []uint8, randomizer *csprng.CSPRNG) ([]uint8, error) {
	N := len(intercepts)

	// assign random coefficients for all the N polynomials
	_, err := randomizer.Read(buffer)
	if err != nil {
		return nil, err
	}

	for p := 0; p < N; p++ {
		s := (degree+1)*p
		e := s + degree+1

		// polynomials[p][0] is the intercept
		// polynomials[p][1:] is the other coefficients that we fill with random
		polynomialP := buffer[s:e]
		polynomialP[0] = intercepts[p]
	}
	return buffer, nil
}

func makePolynomials(intercepts []uint8, degree int) ([][]uint8, error) {
	N := len(intercepts)
	polynomials := newMatrix(N, degree+1)
	coefficients := make([]byte, degree*N)

	// Assign random co-efficients to all the N polynomials
	if _, err := rand.Read(coefficients); err != nil {
		return nil, err
	}

	startIdx := 0
	for p := 0; p < N; p++ {
		polynomials[p][0] = intercepts[p]                                // polynomials[p][0] is the intercept
		copy(polynomials[p][1:], coefficients[startIdx:startIdx+degree]) // polynomials[p][1:] is the other coefficients
		startIdx += degree
	}

	return polynomials, nil
}

func makePolynomialsWithRandomizer(intercepts []uint8, degree int, randomizer *csprng.CSPRNG) ([][]uint8, error) {
	N := len(intercepts)
	polynomials := make([][]byte, N)
	coefficients := make([]byte, (degree+1)*N)

	// Assign random co-efficients to all the N polynomials
	if _, err := randomizer.Read(coefficients); err != nil {
		return nil, err
	}

	for p := 0; p < N; p++ {
		s := (degree+1)*p
		e := s + degree+1

		polynomials[p] = coefficients[s:e]	// polynomials[p][1:] is the other coefficients
		polynomials[p][0] = intercepts[p]   // polynomials[p][0] is the intercept
	}

	return polynomials, nil
}

func transpose(slice [][]uint8) [][]uint8 {
	xl := len(slice[0])
	yl := len(slice)
	result := newMatrix(xl, yl)
	for i := 0; i < xl; i++ {
		for j := 0; j < yl; j++ {
			result[i][j] = slice[j][i]
		}
	}
	return result
}

func transposeMatrixBuffer(dest, source []uint8, rowLen int) {
	colLen := len(source)/rowLen
	curSourceCol := 0
	curSourceRow := 0
	for i := 0; i < len(source); i++ {
		dest[i] = source[rowLen*curSourceRow + curSourceCol]
		curSourceRow++
		if curSourceRow == colLen {
			curSourceRow = 0
			curSourceCol++
		}
	}
}

func newMatrix(r, c int) [][]uint8 {
	a := make([]uint8, r*c)
	m := make([][]uint8, r)
	lo, hi := 0, c
	for i := range m {
		m[i] = a[lo:hi:hi]
		lo, hi = hi, hi+c
	}
	return m
}

// evaluatePolynomialsAt assumes x is not 0.
// coefficients is a ((degree+1)xN) matrix
func evaluatePolynomialsAt(coefficients [][]uint8, x uint8, out []uint8) {
	N := len(coefficients[0])
	degree := len(coefficients) - 1

	resultBuff := polynomialBufferPool.Get()
	defer polynomialBufferPool.Put(resultBuff)
	resultBuff.Reset()
	resultBuff.Grow(N)
	result := resultBuff.Bytes()[0:N]

	// Compute the value at x in all the N polynomials using Horner's method.
	copy(result, coefficients[degree])
	for i := degree - 1; i >= 0; i-- {
		result = gf.AddVector(coefficients[i], gf.MulConstVector(x, result))
	}
	copy(out[:N], result)
}

func evaluatePolynomialsAtWithCoefficientsBuffer(coefficientsBuff []uint8, rowLen int, x uint8, out []uint8) {
	degree := len(coefficientsBuff)/rowLen-1

	resultBuff := polynomialBufferPool.Get()
	defer polynomialBufferPool.Put(resultBuff)
	resultBuff.Reset()
	resultBuff.Grow(rowLen)
	result := resultBuff.Bytes()[0:rowLen]

	// Compute the value at x in all the N polynomials using Horner's method.
	s := degree*rowLen
	e := s+rowLen
	copy(result, coefficientsBuff[s:e])
	for i := degree - 1; i >= 0; i-- {
		s = i*rowLen
		e = s+rowLen
		result = gf.AddVector(coefficientsBuff[s:e], gf.MulConstVector(x, result))
	}
	copy(out[:rowLen], result)
}

// genericEvaluatePolynomialsAt assumes x is not 0.
// coefficients is a ((degree+1)xN) matrix
func genericEvaluatePolynomialsAt(coefficients [][]uint8, x uint8, out []uint8) {
	N := len(coefficients[0])
	degree := len(coefficients) - 1
	result := make([]uint8, N)

	// Compute the value at x in all the N polynomials using Horner's method.
	copy(result, coefficients[degree])
	for i := degree - 1; i >= 0; i-- {
		result = gf.AddVectorGeneric(coefficients[i], gf.MulConstVectorGeneric(x, result))
	}
	copy(out[:N], result)
}

// polynomial represents a polynomial of arbitrary degree
type polynomial struct {
	coefficients []uint8
}

// makePolynomial constructs a random polynomial of the given
// degree but with the provided intercept value.
func makePolynomial(intercept, degree uint8) (polynomial, error) {
	// Create a wrapper
	p := polynomial{
		coefficients: make([]byte, degree+1),
	}

	// Ensure the intercept is set
	p.coefficients[0] = intercept

	// Assign random co-efficients to the polynomial
	if _, err := rand.Read(p.coefficients[1:]); err != nil {
		return p, err
	}

	return p, nil
}

// add combines two numbers in GF(2^8)
// This can also be used for subtraction since it is symmetric.
func add(a, b uint8) uint8 {
	return a ^ b
}

// div divides two numbers in GF(2^8)
func div(a, b uint8) uint8 {
	if b == 0 {
		// leaks some timing information but we don't care anyways as this
		// should never happen, hence the panic
		panic("divide by zero")
	}

	log_a := logTable[a]
	log_b := logTable[b]
	diff := ((int(log_a) - int(log_b)) + 255) % 255

	ret := int(expTable[diff])

	// Ensure we return zero if a is zero but aren't subject to timing attacks
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeByteEq(a, 0), 0, ret)
	return uint8(ret)
}

// mult multiplies two numbers in GF(2^8)
func mult(a, b uint8) (out uint8) {
	log_a := logTable[a]
	log_b := logTable[b]
	sum := (int(log_a) + int(log_b)) % 255

	ret := int(expTable[sum])

	// Ensure we return zero if either a or b are zero but aren't subject to
	// timing attacks
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeByteEq(a, 0), 0, ret)
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeByteEq(b, 0), 0, ret)

	return uint8(ret)
}

// evaluate returns the value of the polynomial for the given x
func (p *polynomial) evaluate(x uint8) uint8 {
	// Special case the origin
	if x == 0 {
		return p.coefficients[0]
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		out = gf.GalAdd(gf.GalMultiply(out, x), coeff)
	}
	return out
}

// interpolatePolynomial takes N sample points and returns
// the value at a given x using lagrange interpolation.
func interpolatePolynomial(x_samples, y_samples []uint8, x uint8) uint8 {
	limit := len(x_samples)
	var result, basis uint8
	for i := 0; i < limit; i++ {
		basis = 1
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			num := add(x, x_samples[j])
			denom := add(x_samples[i], x_samples[j])
			term := div(num, denom)
			basis = mult(basis, term)
		}
		group := mult(y_samples[i], basis)
		result = add(result, group)
	}
	return result
}
