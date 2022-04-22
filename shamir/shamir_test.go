package shamir

import (
	"github.com/fadhilkurnia/shamir/csprng"
	hcShamir "github.com/hashicorp/vault/shamir"
	"math/rand"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestSplitCombine(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")

	shares, _ := Split(secretMsg, 4, 2)
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombineVaryT(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")
	maxParts := 20

	for th := 2; th <= maxParts; th++ {
		shares, _ := Split(secretMsg, maxParts, th)
		combinedShares, _ := Combine(shares)

		isEqual := reflect.DeepEqual(secretMsg, combinedShares)
		if !isEqual {
			t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
		}
	}
}

func TestSplitCombineWithRandomizerOld(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")

	r := csprng.NewCSPRNG()
	shares, _ := SplitWithRandomizerOld(secretMsg, 4, 2, r)
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombineWithRandomizer(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")

	r := csprng.NewCSPRNG()
	shares, _ := SplitWithRandomizer(secretMsg, 4, 2, r)
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombineWithRandomizer2(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")

	r := csprng.NewCSPRNG()
	shares, _ := SplitWithRandomizer(secretMsg, 4, 4, r)
	combinedShares, _ := Combine(shares)

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitIncreasingSize(t *testing.T) {
	for size := 10; size < 1_000; size += 10 {
		secretMsg := make([]byte, size)
		rand.Read(secretMsg)

		start := time.Now()
		_, err := Split(secretMsg, 4, 2)
		dur := time.Since(start)
		if err != nil {
			t.Error(err)
		}

		t.Logf("size: %d  time: %d", size, dur.Nanoseconds())
	}
	for size := 1000; size < 1_000_000; size += 1000 {
		secretMsg := make([]byte, size)
		rand.Read(secretMsg)

		start := time.Now()
		_, err := Split(secretMsg, 4, 2)
		dur := time.Since(start)
		if err != nil {
			t.Error(err)
		}

		t.Logf("size: %d  time: %d", size, dur.Nanoseconds())
	}
}

func TestSplit100NoDelay(t *testing.T) {
	secretMsg := make([]byte, 100)
	var result [][]byte
	rand.Read(secretMsg)
	N := 1_000

	durations := make([]time.Duration, N)

	sumtime := int64(0)
	for i := 0; i < N; i++ {
		ls :=time.Now()
		result, _ = Split(secretMsg, 4, 2)
		durations[i] = time.Since(ls)
		sumtime += durations[i].Nanoseconds()
	}

	t.Logf("(%d) avg. processing time %vns", len(result), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestSplit100And3msDelay(t *testing.T) {
	secretMsg := make([]byte, 100)
	var result [][]byte
	rand.Read(secretMsg)
	N := 1_000

	durations := make([]time.Duration, N)

	sumtime := int64(0)
	for i := 0; i < N; i++ {
		ls :=time.Now()
		result, _ = Split(secretMsg, 4, 2)
		durations[i] = time.Since(ls)
		sumtime += durations[i].Nanoseconds()
		time.Sleep(3 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(result), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestSplit100And5msDelay(t *testing.T) {
	secretMsg := make([]byte, 100)
	var result [][]byte
	rand.Read(secretMsg)
	N := 1_000

	durations := make([]time.Duration, N)

	sumtime := int64(0)
	for i := 0; i < N; i++ {
		ls :=time.Now()
		result, _ = Split(secretMsg, 4, 2)
		durations[i] = time.Since(ls)
		sumtime += durations[i].Nanoseconds()
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(result), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestSplit100And10msDelay(t *testing.T) {
	secretMsg := make([]byte, 100)
	var result [][]byte
	rand.Read(secretMsg)
	N := 1_000

	durations := make([]time.Duration, N)

	sumtime := int64(0)
	for i := 0; i < N; i++ {
		ls :=time.Now()
		result, _ = Split(secretMsg, 4, 2)
		durations[i] = time.Since(ls)
		sumtime += durations[i].Nanoseconds()
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(result), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestSplitCombine1K(t *testing.T) {
	secretMsg := make([]byte, 1_000)
	rand.Read(secretMsg)

	shares, _ := Split(secretMsg, 4, 2)
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombine10K(t *testing.T) {
	secretMsg := make([]byte, 10_000)
	rand.Read(secretMsg)

	shares, _ := Split(secretMsg, 4, 2)
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombine100K(t *testing.T) {
	secretMsg := make([]byte, 100_000)
	rand.Read(secretMsg)

	shares, _ := Split(secretMsg, 4, 2)
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombineVault(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")

	hcShares, _ := hcShamir.Split(secretMsg, 4, 2)
	shares, _ := Split(secretMsg, 4, 2)

	hcCombinedShares, _ := hcShamir.Combine(hcShares[:2])
	combinedShares, _ := Combine(shares[:2])

	isEqual := reflect.DeepEqual(hcCombinedShares, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(hcCombinedShares), string(combinedShares))
	}
}

func TestParallelSplitWithRandomizer(t *testing.T) {
	numThreads := runtime.NumCPU()
	numRequest := 1_000_000
	reqSize := 50

	buff := make([]byte, reqSize)
	rand.Read(buff)
	input := make(chan []byte, 1_000)
	output := make(chan [][]byte, 1_000)

	for i := 0; i < numThreads; i++ {
		go func() {
			r := csprng.NewCSPRNG()
			for in := range input {
				res, _ := SplitWithRandomizer(in, 4, 2, r)
				output <- res
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < numRequest; i++ {
			in := make([]byte, 50)
			copy(in, buff)
			input <- in
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRequest; i++ {
			<-output
		}
	}()
	wg.Wait()

	dur := time.Since(start)
	t.Log("duration ", dur)
	t.Log("capacity ", float64(numRequest)/dur.Seconds(), "req/s", numThreads, "threads")
}

func TestParallelSplit(t *testing.T) {
	numThreads := runtime.NumCPU()
	numRequest := 1_000_000
	reqSize := 50

	buff := make([]byte, reqSize)
	rand.Read(buff)
	input := make(chan []byte, 1_000)
	output := make(chan [][]byte, 1_000)

	for i := 0; i < numThreads; i++ {
		go func() {
			for in := range input {
				res, _ := Split(in, 4, 2)
				output <- res
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < numRequest; i++ {
			in := make([]byte, 50)
			copy(in, buff)
			input <- in
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRequest; i++ {
			<-output
		}
	}()
	wg.Wait()

	dur := time.Since(start)
	t.Log("duration ", dur)
	t.Log("capacity ", float64(numRequest)/dur.Seconds(), "req/s", numThreads, "threads")
}