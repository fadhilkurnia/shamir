package krawczyk

import (
	"bytes"
	"fmt"
	"github.com/fadhilkurnia/shamir/csprng"
	"github.com/klauspost/reedsolomon"
	"math/rand"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestEncryptDecrypt(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog")
	key := []byte("1234512345123451")
	ciphertext, err := encrypt(secretMsg, key)
	if err != nil {
		t.Errorf("failed to encrypt the data: %v", err)
		return
	}
	plaintext, err := decrypt(ciphertext, key)
	if err != nil {
		t.Errorf("failed to decrypt the ciphertext %v", err)
		return
	}
	t.Logf("original size: %d bytes, ciphertext size: %d bytes.", len(secretMsg), len(ciphertext))

	isEqual := reflect.DeepEqual(secretMsg, plaintext)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(plaintext))
	}
}

func TestReedSolomonSplit(t *testing.T) {
	rawData := []byte("The quick brown fox jumps over the lazy dog.xxxxxx")
	parts := 5
	threshold := 2

	encoder, err := reedsolomon.New(threshold, parts-threshold)
	if err != nil {
		t.Error(err)
	}
	encodedSecret, err := encoder.Split(rawData)
	if err != nil {
		t.Error(err)
	}
	if err := encoder.Encode(encodedSecret); err != nil {
		t.Error(err)
	}

	t.Logf("original len: %d, encoded len: %d", len(rawData), len(encodedSecret[0]))

	encodedSecret[0] = nil
	encodedSecret[1] = nil
	encodedSecret[4] = nil
	err = encoder.ReconstructData(encodedSecret)
	if err != nil {
		t.Error(err)
	}
}

func TestSplitLen(t *testing.T) {
	parts := 5
	threshold := 2

	for scrtLen := 1; scrtLen <= 5000; scrtLen++ {
		secretMsg := make([]byte, scrtLen)
		rand.Read(secretMsg)
		shares, err := Split(secretMsg, parts, threshold)
		if err != nil {
			fmt.Printf("failed to split the message: %v", err)
		}
		t.Logf("n:%d, t:%d, original len: %d, encoded len: %d", parts, threshold, len(secretMsg), len(shares[0]))
	}

}

func TestSplitCombine(t *testing.T) {
	secretMsg := []byte("01234567891234567890012345678909876543210987654321")
	parts := 5
	threshold := 2

	shares, err := Split(secretMsg, parts, threshold)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}
	combinedShares, err := Combine(shares[:threshold], parts, threshold)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
	expectedLen := len(secretMsg)/(threshold) + 1 + 16 + 4 + 1 // 1 byte partID, 16 bytes key, 4 bytes length, 1 bytes ss metadata
	if len(secretMsg) % (threshold) != 0 {
		expectedLen += 1
	}
	if len(shares[0]) != expectedLen {
		t.Errorf("the expected length of a single share is %d, but got %d", expectedLen, len(shares[0]))
	}
}

func TestSplitCombine2(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog.")

	shares, err := Split(secretMsg, 5, 2)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}
	shares[1] = nil
	shares[3] = nil
	shares[4] = nil
	combinedShares, err := Combine(shares, 5, 2)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombine3(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog.")
	parts := 2
	threshold := 2

	shares, err := Split(secretMsg, parts, threshold)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}
	combinedShares, err := Combine(shares, parts, threshold)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombine1MB(t *testing.T) {
	secretMsg := make([]byte, 1_000_000)
	rand.Read(secretMsg)
	parts := 5
	threshold := 2

	shares, err := Split(secretMsg, parts, threshold)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}

	combinedShares, err := Combine(shares, parts, threshold)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

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

func TestSplitCombineZeroK(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")

	shares, err := Split(secretMsg, 4, 4)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}
	combinedShares, err := Combine(shares, 4, 4)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

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
		combinedShares, _ := Combine(shares, maxParts, th)

		isEqual := reflect.DeepEqual(secretMsg, combinedShares)
		if !isEqual {
			t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
		}
	}
}

func TestReedSolomonSplit2(t *testing.T) {
	originalText := []byte("The quick brown fox jumps over the lazy dog")
	enc, _ := reedsolomon.New(2, 2)
	encoded, _ := enc.Split(originalText)
	resBuffer := bytes.Buffer{}
	enc.Join(&resBuffer, encoded[:3], len(originalText))
	isEqual := reflect.DeepEqual(resBuffer.Bytes(), originalText)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(originalText), string(resBuffer.Bytes()))
	}
}


func TestReedSolomonNoDelay(t *testing.T) {
	originalData := make([]byte, 10_000)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		enc, _ := reedsolomon.New(2, 2)
		startTime := time.Now()
		encoded, _ := enc.Split(originalData)
		_ = enc.Encode(encoded)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestReedSolomon5msDelay(t *testing.T) {
	originalData := make([]byte, 10_000)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		enc, _ := reedsolomon.New(2, 2)
		startTime := time.Now()
		encoded, _ := enc.Split(originalData)
		_ = enc.Encode(encoded)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestReedSolomon10msDelay(t *testing.T) {
	originalData := make([]byte, 10_000)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		enc, _ := reedsolomon.New(2, 2)
		startTime := time.Now()
		encoded, _ := enc.Split(originalData)
		_ = enc.Encode(encoded)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
	t.Logf("%v", durations)
}

func TestParallelSplitWithRandomizer(t *testing.T) {
	numThreads := runtime.NumCPU()
	numRequest := 100_000
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
	numRequest := 100_000
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