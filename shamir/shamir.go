package shamir

import (
	"fmt"
	"github.com/fadhilkurnia/shamir/csprng"
	"github.com/fadhilkurnia/shamir/utils"
	"log"
	"math/rand"
	"sync"
)

const (
	// ShareOverhead is the byte size overhead of each share
	// when using Split on a secret. This is caused by appending
	// a one byte tag to the share.
	ShareOverhead = 1
)

var bPool *utils.BytesBufferPool

func init() {
	bPool = utils.NewBytesBufferPool(0)
}

// Split takes an arbitrarily long secret and generates a `parts`
// number of shares, `threshold` of which are required to reconstruct
// the secret. The parts and threshold must be at least 2, and less
// than 256. The returned shares are each one byte longer than the secret
// as they attach a tag used to reconstruct the secret.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	// Generate random list of x coordinates
	xCoordinates := rand.Perm(255)

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	// part1: {y1, y2, .., yN, x}
	// part2: {y1, y2, .., yN, x}
	// ...
	// partN: {y1, y2, .., yN, x}
	out := make([][]byte, parts)
	buff := make([]byte, (len(secret)+1)*parts)
	for idx := range out {
		s := (len(secret)+1)*idx
		e := s + len(secret)+1
		out[idx] = buff[s:e]
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	N := len(secret)
	degree := threshold-1

	// get temporary buffers from pool
	polBytesBuff := bPool.Get()
	defer bPool.Put(polBytesBuff)
	polBytesBuff.Reset()
	polBytesBuff.Grow((degree+1)*N)
	polBuff := polBytesBuff.Bytes()[0:(degree+1)*N]

	// Construct a random polynomial for N bytes of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	// polynomials is a matrix with (N x degree+1) dimension
	polynomials, err := makePolynomialsWithBuff(secret, degree, polBuff)
	if err != nil {
		return nil, fmt.Errorf("failed to generate polynomial: %v", err)
	}

	// prepare temporary buffer for the transpose of the polynomials
	polTransposeBytesBuff := bPool.Get()
	defer bPool.Put(polTransposeBytesBuff)
	polTransposeBytesBuff.Reset()
	polTransposeBytesBuff.Grow(len(polynomials))

	// transposing polynomials for polynomial evaluation
	coefficientBuff := polTransposeBytesBuff.Bytes()[0:len(polynomials)]
	transposeMatrixBuffer(coefficientBuff, polynomials, degree+1)

	// evaluating the polynomials at the secret points x
	for i := 0; i < parts; i++ {
		evaluatePolynomialsAtWithCoefficientsBuffer(coefficientBuff, N, uint8(xCoordinates[i])+1, out[i][0:N])
	}

	// Return the encoded secrets
	return out, nil
}

// SplitWithRandomizerOld will be deprecated soon
func SplitWithRandomizerOld(secret []byte, parts, threshold int, randomizer *csprng.CSPRNG) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	// Generate random list of x coordinates
	xCoordinates := randomizer.Perm(255)

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	// part1: {y1, y2, .., yN, x}
	// part2: {y1, y2, .., yN, x}
	// ...
	// partN: {y1, y2, .., yN, x}
	out := make([][]byte, parts)
	buff := make([]byte, (len(secret)+1)*parts)
	for idx := range out {
		s := (len(secret)+1)*idx
		e := s + len(secret)+1
		out[idx] = buff[s:e]
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Construct a random polynomial for N bytes of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	// polynomials is a matrix with (N x degree+1) dimension
	polynomials, err := makePolynomialsWithRandomizer(secret, threshold-1, randomizer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate polynomial: %v", err)
	}
	coefficients := transpose(polynomials)
	for i := 0; i < parts; i++ {
		evaluatePolynomialsAt(coefficients, uint8(xCoordinates[i])+1, out[i])
	}

	// Return the encoded secrets
	return out, nil
}

func SplitWithRandomizer(secret []byte, parts, threshold int, randomizer *csprng.CSPRNG) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	// Generate random list of x coordinates
	xCoordinates := randomizer.GetUniqueBytes(byte(parts))

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	// part1: {y1, y2, .., yN, x}
	// part2: {y1, y2, .., yN, x}
	// ...
	// partN: {y1, y2, .., yN, x}
	out := make([][]byte, parts)
	buff := make([]byte, (len(secret)+1)*parts)
	for idx := range out {
		s := (len(secret)+1)*idx
		e := s + len(secret)+1
		out[idx] = buff[s:e]
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	N := len(secret)
	degree := threshold-1

	// get temporary buffers from pool
	polBytesBuff := bPool.Get()
	defer bPool.Put(polBytesBuff)
	polBytesBuff.Reset()
	polBytesBuff.Grow((degree+1)*N)
	polBuff := polBytesBuff.Bytes()[0:(degree+1)*N]

	// Construct a random polynomial for N bytes of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	// polynomials is a matrix with (N x degree+1) dimension
	polynomials, err := makePolynomialsWithBuffAndRandomizer(secret, degree, polBuff, randomizer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate polynomial: %v", err)
	}

	// prepare temporary buffer for the transpose of the polynomials
	polTransposeBytesBuff := bPool.Get()
	defer bPool.Put(polTransposeBytesBuff)
	polTransposeBytesBuff.Reset()
	polTransposeBytesBuff.Grow(len(polynomials))

	// transposing polynomials for polynomial evaluation
	coefficientBuff := polTransposeBytesBuff.Bytes()[0:len(polynomials)]
	transposeMatrixBuffer(coefficientBuff, polynomials, degree+1)

	// evaluating the polynomials at the secret points x
	for i := 0; i < parts; i++ {
		evaluatePolynomialsAtWithCoefficientsBuffer(coefficientBuff, N, uint8(xCoordinates[i])+1, out[i][0:N])
	}

	// Return the encoded secrets
	return out, nil
}

func SplitGeneric(secret []byte, parts, threshold int) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	// Generate random list of x coordinates
	xCoordinates := rand.Perm(255)

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	// part1: {y1, y2, .., yN, x}
	// part2: {y1, y2, .., yN, x}
	// ...
	// partN: {y1, y2, .., yN, x}
	out := make([][]byte, parts)
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Construct a random polynomial for N bytes of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	// polynomials is a matrix with (N x degree) dimension
	polynomials, err := makePolynomials(secret, threshold-1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate polynomial: %v", err)
	}
	coefficients := transpose(polynomials)
	for i := 0; i < parts; i++ {
		genericEvaluatePolynomialsAt(coefficients, uint8(xCoordinates[i])+1, out[i])
	}

	// Return the encoded secrets
	return out, nil
}

func SplitP(secret []byte, parts, threshold int) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	// Generate random list of x coordinates
	xCoordinates := rand.Perm(255)

	// Allocate the output array, initialize the final byte
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	out := make([][]byte, parts)
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Construct a random polynomial for each byte of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	idx := uint32(0)
	secretLen := uint32(len(secret))
	var wg sync.WaitGroup
	for idx < secretLen {

		endIdx := idx + 1024
		if endIdx > secretLen {
			endIdx = secretLen
		}

		wg.Add(1)
		go func(startIdx, endIdx uint32, values []byte) {
			defer wg.Done()

			crtIdx := startIdx
			for _, val := range values {
				p, err := makePolynomial(val, uint8(threshold-1))
				if err != nil {
					log.Fatalf("failed to generate polynomial: %s", err.Error())
				}

				// Generate a `parts` number of (x,y) pairs
				// We cheat by encoding the x value once as the final index,
				// so that it only needs to be stored once.
				for i := 0; i < parts; i++ {
					x := uint8(xCoordinates[i]) + 1
					y := p.evaluate(x)
					out[i][crtIdx] = y
				}
				crtIdx += 1
			}

		}(idx, endIdx, secret[idx:endIdx])
		idx = endIdx
	}

	wg.Wait()

	// Return the encoded secrets
	return out, nil
}

// Combine is used to reverse a Split and reconstruct a secret
// once a `threshold` number of parts are available.
func Combine(parts [][]byte) ([]byte, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	firstPartLen := len(parts[0])
	if firstPartLen < 2 {
		return nil, fmt.Errorf("parts must be at least two bytes")
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	// Create a buffer to store the reconstructed secret
	secret := make([]byte, firstPartLen-1)

	// Buffer to store the samples
	x_samples := make([]uint8, len(parts))
	y_samples := make([]uint8, len(parts))

	// Set the x value for each sample and ensure no x_sample values are the same,
	// otherwise div() can be unhappy
	checkMap := map[byte]bool{}
	for i, part := range parts {
		samp := part[firstPartLen-1]
		if exists := checkMap[samp]; exists {
			return nil, fmt.Errorf("duplicate part detected")
		}
		checkMap[samp] = true
		x_samples[i] = samp
	}

	// Reconstruct each byte
	for idx := range secret {
		// Set the y value for each sample
		for i, part := range parts {
			y_samples[i] = part[idx]
		}

		// Interpolate the polynomial and compute the value at 0
		val := interpolatePolynomial(x_samples, y_samples, 0)

		// Evaluate the 0th value to get the intercept
		secret[idx] = val
	}
	return secret, nil
}

// Regenerate regenerates more secret shares given enough secret-shares
// to reconstruct the secret polynomial (secret value). Regenerate is
// similar with Combine, but we keep the original polynomial instead
// of regenerating another secret polynomial.
func Regenerate(parts [][]byte, numNewShares int) ([][]byte, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	firstPartLen := len(parts[0])
	if firstPartLen < 2 {
		return nil, fmt.Errorf("parts must be at least two bytes")
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	// TODO: make a more efficient version of this by allocating less memory
	// Create buffer to store the new shares
	newShares := make([][]byte, numNewShares)
	x_samples := make([]uint8, len(parts))
	y_samples := make([]uint8, len(parts))
	newXs := make([]byte, numNewShares)

	// Set the x value for each sample and ensure no x_sample values are the same,
	// otherwise div() can be unhappy
	checkMap := map[byte]bool{}
	for _, part := range parts {
		samp := part[firstPartLen-1]
		if exists := checkMap[samp]; exists {
			return nil, fmt.Errorf("duplicate part detected")
		}
		checkMap[samp] = true
	}

	// generate new random x
	if _, err := rand.Read(newXs); err != nil {
		return nil, fmt.Errorf("failed to generate new random x: %v", err)
	}
	// ensure no duplicate x generated
	for _, nx := range newXs {
		exists := checkMap[nx]
		for exists {
			nx = byte(rand.Uint32())
			exists = checkMap[nx]
		}
		checkMap[nx] = true
	}

	for i, share := range parts {
		x_samples[i] = share[firstPartLen-1]
	}
	for k:=0; k < numNewShares; k++ {
		newShares[k] = make([]byte, firstPartLen) // TODO: make this more efficient by allocating with buffer pool
		newShares[k][firstPartLen-1] = newXs[k]
		for j := 0; j < firstPartLen-1; j++ {
			for i, share := range parts {
				y_samples[i] = share[j]
			}
			newShares[k][j] = interpolatePolynomial(x_samples, y_samples, newXs[k])
		}
	}

	return newShares, nil
}
