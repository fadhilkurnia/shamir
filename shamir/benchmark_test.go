package shamir

import (
	crand "crypto/rand"
	"math/rand"
	"runtime"
	"testing"
)

// TODO: implement this
// func BenchmarkMakePolynomials()
// func BenchmarkEvaluatePolynomialsAt()

func BenchmarkBaseline(b *testing.B) {
	numWorker := runtime.GOMAXPROCS(-1)
	workAmount := 100_000
	b.SetBytes(int64(workAmount) * int64(numWorker) * 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := make(chan int64)
		res := make(chan int64)

		// spawning workers, they are waiting for job
		for j := 0; j < numWorker; j++ {
			go func() {
				// wait for input
				input := <- c

				// do some busy works
				x := make([]int64, workAmount)
				for k := 0; k < len(x)-1; k++ {
					x[k] = input + x[k+1]
				}
				res <- x[len(x)-1]
			}()
		}

		// send job to worker
		for j := 0; j < numWorker; j++ {
			c <- 123
		}

		// consume for the results
		for j := 0; j < numWorker; j++ {
			<- res
		}
	}
}


func BenchmarkRandom(b *testing.B) {
	numWorker := runtime.GOMAXPROCS(-1)
	workAmount := 100_000
	b.SetBytes(int64(workAmount) * int64(numWorker))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := make(chan byte, 1)

		// spawning workers
		for j := 0; j < numWorker; j++ {
			go func(input int64, c chan byte) {
				// do some busy works, spinning the core.
				x := make([]byte, workAmount)
				rand.Read(x)
				c <- x[len(x)-1]
			}(rand.Int63(), c)
		}

		// consuming results
		for j := 0; j < numWorker; j++ {
			<- c
		}
	}
}

func BenchmarkRandomCrypto(b *testing.B) {
	numWorker := runtime.GOMAXPROCS(-1)
	b.SetBytes(1_000 * int64(numWorker))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := make(chan byte, 1)

		// spawning workers
		for j := 0; j < numWorker; j++ {
			go func(input int64, c chan byte) {

				// do some busy works
				x := make([]byte, 1_000)
				crand.Read(x)
				c <- x[len(x)-1]
			}(rand.Int63(), c)
		}

		// consuming results
		for j := 0; j < numWorker; j++ {
			<- c
		}
	}
}
