package shamir

import (
	"fmt"
	"github.com/fadhilkurnia/shamir/csprng"
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
		evaluatePolynomialsAt(coefficients, uint8(xCoordinates[i])+1, out[i])
	}

	// Return the encoded secrets
	return out, nil
}

// SplitWithRandomizerOld is exactly the same with Split but with randomizer provided by the caller
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
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Construct a random polynomial for N bytes of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	// polynomials is a matrix with (N x degree) dimension
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
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Construct a random polynomial for N bytes of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	// polynomials is a matrix with (N x degree) dimension
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
