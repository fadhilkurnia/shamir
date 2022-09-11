# 🐿️ Go-Shamir: Fast Shamir Secret Sharing in Pure Go 🔑

This library offers higher throughput and lower latency to generate shamir secret-sharing, compared to [Hashicorp's implementation](https://github.com/hashicorp/vault/tree/main/shamir) in Vault. Our benchmark shows **up to 80x better throughput!**

Modifications from the original Hashicorp's implementation:
- Support arbitrary length secret data.
- Straightforward API interfaces for splitting and combining secret shares, similar as the original implementation by Hashicorp.
- Optimized for doing threshold secret sharing for **large data** using vectorized operation which is more cache-friendly.
- For the Galois arithmatics used in the seret-shares generation, we use **SIMD support** for ARM64 and AMD64 architecture.
- For higher throughput, we use [AES counter mode with AES-NI](https://github.com/starius/aesctrat) as the randomization source (computationally secure psuedo-random number generator/CSPRNG) instead of Go standard `math/rand` or `crypto/rand`.
- Implementation of SSMS (Secret-Sharing Made Short) which combines Shamir's secret sharing and reed-solomon erasure coding for smaller shares' size.

This implementation is possible because of these amazing works:
- [Hashicorp secret sharing from Vault](https://github.com/hashicorp/vault/tree/main/shamir)
- [GF(2^8) with SIMD support from Klaus Post's ReedSolomon Encoding implementation](https://github.com/klauspost/reedsolomon)

Benchmark result using one core in Macbook Pro with M1 chip can be seen below. Here we generate 5 secret-shares from 1K, 10K, and 1M bytes of secret data which can be recovered by combining t=2 shares.
```
$ go test -cpu 1 -bench BenchmarkSplitHashicorp
goos: darwin
goarch: arm64
pkg: github.com/fadhilkurnia/shamir
BenchmarkSplitHashicorp1K  	    3614	    328623 ns/op	   3.04 MB/s
BenchmarkSplitHashicorp10K 	     369	   3212093 ns/op	   3.11 MB/s
BenchmarkSplitHashicorp1M  	       3	 335963042 ns/op	   3.12 MB/s

$ go test -cpu 1 -bench BenchmarkSplitGoShamir
goos: darwin
goarch: arm64
pkg: github.com/fadhilkurnia/shamir
BenchmarkSplitGoShamir1K  	  135366	      8785 ns/op	 113.83 MB/s
BenchmarkSplitGoShamir10K 	   25412	     46940 ns/op	  21.30 MB/s
BenchmarkSplitGoShamir1M  	     276	   4366021 ns/op	 240.17 MB/s
```
Here we can see that Go-Shamir provides up to 80x the throughput of Hashicorp's implementation! 

Note: we remove the use of `ConstantTimeSelect()` and we have not tested the implementation for any timing attacks. So use the library with caution :)


## What make this implementation faster compared to Hashicorp Vault?
### More cache-friendly implementation
If you have taken any computer system or architecture course, you might aware that we can have faster code if we minimize CPU cache-miss by processing "consecutive" data, not processing data that are "far" frome ach other. The classic example is shown in this [article](https://levelup.gitconnected.com/c-programming-hacks-4-matrix-multiplication-are-we-doing-it-right-21a9f1cbf53); changing the iteration order when doing matrix multiplication can lower the execution time.

In the original implementation, it creates polynomial for each byte of secret data one-by-one. In this implementation, we immediately create polynomials for all the bytes.

Modified [code](https://github.com/fadhilkurnia/shamir/blob/115fadf281d3c13764495ed4f13fbaef1f3d603c/shamir/polynomial.go#L10):
```
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
```

Original [implementation](https://github.com/hashicorp/vault/blob/f305c4d4d1897144d7853d34e73559f2f5ff60f2/shamir/shamir.go#L25):
```
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
```

### Laveraging SIMD instructions
We try to extensively use SIMD instruction in this library. For example, we use SIMD for the galois add operation, as can be seen [here](https://github.com/fadhilkurnia/shamir/blob/115fadf281d3c13764495ed4f13fbaef1f3d603c/galois/vector_amd64.go#L107); there we can simultaneously (in one CPU cycle) execute add operation for up to 64 bytes of data. The original implementation do the add operation one byte at a time, as can be seen below:

Original [implementation](https://github.com/hashicorp/vault/blob/f305c4d4d1897144d7853d34e73559f2f5ff60f2/shamir/shamir.go#L118):
```
// add combines two numbers in GF(2^8)
// This can also be used for subtraction since it is symmetric.
func add(a, b uint8) uint8 {
	return a ^ b
}
```

### More performant randomization
Randomization is an important building block for shamir implementation, it is used to generate random polynomial and random points on the polynomial. As shown in this [paper titled "How to Best Share a Big Secret"](https://dl.acm.org/doi/pdf/10.1145/3211890.3211896) (Table 3), the randomization easily becomes the bottleneck. Using computationally secure pseudo random generator (CSPRNG), AES in counter mode, is the most performant randomization. That is also the case since most of the modern CPU provide native instruction for AES operation, such as [AES-NI](https://www.intel.com/content/www/us/en/architecture-and-technology/advanced-encryption-standard-aes/data-protection-aes-general-technology.html) in Intel chip or [similar instructions](https://en.wikipedia.org/wiki/AES_instruction_set) in other chip. Therefore, in this implementation we use AES in counter mode as the source of randomization, and it uses native AES instructions from the chip.
