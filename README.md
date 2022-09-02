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

Note: we remove the use of `ConstantTimeSelect()` and we have not tested the implementation for any timing attacks. So use with caution :)

