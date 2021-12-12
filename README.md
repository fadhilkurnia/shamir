# 🐿️ Go-Shamir: Fast Shamir Secret Sharing in Pure Go 🔑

Features:
- Support arbitrary length secret data
- Straightforward API interfaces for splitting and combining secret shares
- Optimized for doing threshold secret sharing for **large data** using vectorized operation
- Using **SIMD support** for ARM64 and AMD64 architecture.

This implementation is possible because of these amazing works:
- [Hashicorp secret sharing from Vault](https://github.com/hashicorp/vault/tree/main/shamir)
- [GF(2^8) with SIMD support from Klaus Post's ReedSolomon Encoding implementation](https://github.com/klauspost/reedsolomon)

Benchmark result using one core in Macbook Pro with M1 chip:
```
$ go test -cpu 1 -bench .
goos: darwin
goarch: arm64
pkg: shamir
BenchmarkGaloisXorGeneric1K 	18647222	        64.50 ns/op	31005.42 MB/s
BenchmarkGaloisXorSIMD1K    	46381665	        25.42 ns/op	78670.45 MB/s
BenchmarkGaloisXorGeneric1M 	   19581	     60942 ns/op	34412.43 MB/s
BenchmarkGaloisXorSIMD1M    	   40009	     29633 ns/op	70769.69 MB/s
BenchmarkGaloisMulGeneric1M 	    2688	    449030 ns/op	4670.41 MB/s
BenchmarkGaloisMulSIMD1M    	   19351	     61056 ns/op	34347.81 MB/s
BenchmarkSplitBase1K        	    3636	    330177 ns/op	   3.03 MB/s
BenchmarkSplitGeneric1K     	   29120	     41614 ns/op	  24.03 MB/s
BenchmarkSplitSIMD1K        	   30367	     40102 ns/op	  24.94 MB/s
BenchmarkSplitBase10K       	     388	   3143499 ns/op	   3.18 MB/s
BenchmarkSplitGeneric10K    	    3795	    308675 ns/op	  32.40 MB/s
BenchmarkSplitSIMD10K       	    3852	    301271 ns/op	  33.19 MB/s
BenchmarkSplitBase1M        	       4	 326285938 ns/op	   3.21 MB/s
BenchmarkSplitGeneric1M     	      30	  34094560 ns/op	  30.75 MB/s
BenchmarkSplitSIMD1M        	      33	  33494491 ns/op	  31.31 MB/s
```

Benchmark result using one core in a machine with Intel Xeon chip:
```
$ go test -cpu 1 -bench .
goos: linux
goarch: amd64
pkg: go-shamir
cpu: Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz
BenchmarkGaloisXorGeneric1K-64    	10004642	       111.0 ns/op	18016.40 MB/s
BenchmarkGaloisXorSIMD1K-64       	28580512	        41.55 ns/op	48140.04 MB/s
BenchmarkGaloisXorGeneric1M-64    	   10000	    115624 ns/op	18137.69 MB/s
BenchmarkGaloisXorSIMD1M-64       	   16065	     76826 ns/op	27297.45 MB/s
BenchmarkGaloisMulGeneric1M-64    	    1742	    654206 ns/op	3205.64 MB/s
BenchmarkGaloisMulSIMD1M-64       	    5854	    206340 ns/op	10163.58 MB/s
BenchmarkSplitBase1K-64           	    1357	    871509 ns/op	   1.15 MB/s
BenchmarkSplitGeneric1K-64        	   18783	     63297 ns/op	  15.80 MB/s
BenchmarkSplitSIMD1K-64           	   19177	     61134 ns/op	  16.36 MB/s
BenchmarkSplitBase10K-64          	     140	   8349773 ns/op	   1.20 MB/s
BenchmarkSplitGeneric10K-64       	    2415	    496347 ns/op	  20.15 MB/s
BenchmarkSplitSIMD10K-64          	    2674	    466353 ns/op	  21.44 MB/s
BenchmarkSplitBase100K-64         	       2	 872514094 ns/op	   1.20 MB/s
BenchmarkSplitGeneric100K-64      	      20	  52584798 ns/op	  19.94 MB/s
BenchmarkSplitSIMD100K-64         	      21	  51210035 ns/op	  20.48 MB/s
```