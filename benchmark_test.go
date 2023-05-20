package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	rand2 "crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/fadhilkurnia/shamir/csprng"
	"github.com/fadhilkurnia/shamir/krawczyk"
	"github.com/fadhilkurnia/shamir/shamir"
	hcShamir "github.com/hashicorp/vault/shamir"
	"github.com/klauspost/reedsolomon"
	"math"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

var bytes100 []byte
var bytes1k []byte
var bytes10k []byte
var bytes1M []byte

func init() {
	bytes100 = make([]byte, 100)
	bytes1k = make([]byte, 1_000)
	bytes10k = make([]byte, 10_000)
	bytes1M = make([]byte, 1024*1024)
	rand.Read(bytes100)
	rand.Read(bytes1k)
	rand.Read(bytes10k)
	rand.Read(bytes1M)
}

func BenchmarkSplitSIMD100(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	e, _ := reedsolomon.New(2, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var results [][]byte
		results, _ = e.Split(bytes1k)
		if len(results) == 0 {
			break
		}
	}
}

func BenchmarkCombineSIMD100(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	e, _ := reedsolomon.New(2, 2)
	var shares [][]byte
	shares, _ = e.Split(bytes1k)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shares[0] = nil
		shares[2] = nil
		e.ReconstructData(shares)
		//recVal, _ := hcShamir.Combine(shares[:2])
		//newShares, _ := hcShamir.Split(recVal, 4, 2)
		//if len(newShares) == 0 {
		//	break
		//}
	}
}

func BenchmarkSplitSIMD100NoDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitSIMD100wDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		for j := 0; j < N*N*N; j++ {
			if j > N*N*N {
				break
			}
		}
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitSIMD100w5msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitSIMD100w10msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitBase1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1k, 5, 2)
	}
}

func BenchmarkSplitGeneric1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes1k, 4, 2)
	}
}

func BenchmarkSplitSIMD1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1k, 4, 2)
	}
}

func BenchmarkSplitBase10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitGeneric10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes10k, 4, 2)
	}
}

func BenchmarkSplitSIMD10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitBase1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1M, 4, 2)
	}
}

func BenchmarkSplitGeneric1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.SplitGeneric(bytes1M, 4, 2)
	}
}

func BenchmarkSplitSIMD1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1M, 4, 2)
	}
}

func BenchmarkSplitCombineSIMD1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ss, _ := shamir.Split(bytes1M, 4, 2)
		_, _ = shamir.Combine(ss)
	}
}

func BenchmarkSplitKrawczyk100(b *testing.B) {
	b.SetBytes(int64(len(bytes100)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var results [][]byte
		results, _ = krawczyk.Split(bytes100, 4, 2)
		if len(results) == 0 {
			break
		}
	}
}

func BenchmarkSplitKrawczyk100NoDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = krawczyk.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitKrawczyk100w5msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitKrawczyk100w10msDelay(t *testing.B) {
	originalData := make([]byte, 100)
	_, _ = rand.Read(originalData)

	N := 1_000
	durations := make([]time.Duration, N)
	sumtime := int64(0)

	for i := 0; i < N; i++ {
		var results [][]byte
		startTime := time.Now()
		results, _ = shamir.Split(originalData, 4, 2)
		durations[i] = time.Since(startTime)
		sumtime += durations[i].Nanoseconds()
		if len(results) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("(%d) avg. processing time %vns", len(durations), sumtime/int64(N))
}

func BenchmarkSplitKrawczyk1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = krawczyk.Split(bytes1k, 4, 2)
	}
}

func BenchmarkSplitKrawczyk10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = krawczyk.Split(bytes10k, 4, 2)
	}
}

func BenchmarkSplitCombineKrawczyk10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ss, _ := krawczyk.Split(bytes10k, 4, 2)
		_, _ = krawczyk.Combine(ss, 4, 2)
	}
}

func BenchmarkSplitHashicorp100b(b *testing.B) {
	b.SetBytes(int64(len(bytes100)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes100, 5, 2)
	}
}

func BenchmarkSplitGoShamir100b(b *testing.B) {
	b.SetBytes(int64(len(bytes100)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes100, 5, 2)
	}
}

func BenchmarkSplitHashicorp1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1k, 5, 2)
	}
}

func BenchmarkSplitGoShamir1K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1k, 5, 2)
	}
}

func BenchmarkSplitHashicorp10K(b *testing.B) {
	b.SetBytes(int64(len(bytes10k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes10k, 5, 2)
	}
}

func BenchmarkSplitGoShamir10K(b *testing.B) {
	b.SetBytes(int64(len(bytes1k)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes10k, 5, 2)
	}
}

func BenchmarkSplitHashicorp1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hcShamir.Split(bytes1M, 5, 2)
	}
}

func BenchmarkSplitGoShamir1M(b *testing.B) {
	b.SetBytes(int64(len(bytes1M)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamir.Split(bytes1M, 5, 2)
	}
}

func TestSplitIncreasingSize(t *testing.T) {
	numTrials := 1000
	sizes := make([]int, 0)
	for size := 10; size < 5_000; size += 10 {
		sizes = append(sizes, size)
	}
	for size := 5_000; size < 200_000; size += 1000 {
		sizes = append(sizes, size)
	}

	f, err := os.Create("data/proc_time.csv")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	_, err = w.WriteString("algo,size(bytes),avg_proc_time(ms),std_err(ms),std_dev(ms)\n")
	if err != nil {
		t.Error(err)
	}

	// shamir secret sharing
	for s := 0; s < len(sizes); s++ {
		size := sizes[s]
		secretMsg := make([]byte, size)
		rand.Read(secretMsg)

		runtime.GC()

		// warmups
		for i := 0; i < 10; i++ {
			_, err := shamir.Split(secretMsg, 5, 2)
			if err != nil {
				t.Error(err)
			}
		}

		durs := make([]time.Duration, numTrials)
		sum := int64(0) // sum is stored in us
		for i := 0; i < numTrials; i++ {
			start := time.Now()
			_, err := shamir.Split(secretMsg, 5, 2)
			durs[i] = time.Since(start)
			sum += durs[i].Microseconds()
			if err != nil {
				t.Error(err)
			}
		}

		// counting average, std.err, and std.dev (in ms)
		avgDur := float64(sum) / 1000.0 / float64(numTrials)
		stdDev := 0.0
		for i := 0; i < numTrials; i++ {
			stdDev += math.Pow(float64(durs[i].Nanoseconds())/1000000.0-avgDur, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(numTrials))
		stdErr := stdDev / math.Sqrt(float64(numTrials))

		// the results are stored in bytes for size, and ms for svg.time and std.err
		_, err = w.WriteString(fmt.Sprintf("shamir,%d,%.4f,%.4f,%.4f\n", size, avgDur, stdErr, stdDev))
		if err != nil {
			t.Error(err)
		}
	}

	// krawczyk secret sharing (ssms)
	for s := 0; s < len(sizes); s++ {
		size := sizes[s]
		secretMsg := make([]byte, size)
		rand.Read(secretMsg)

		runtime.GC()

		// warmups
		for i := 0; i < 10; i++ {
			_, err := krawczyk.Split(secretMsg, 5, 2)
			if err != nil {
				t.Error(err)
			}
		}

		durs := make([]time.Duration, numTrials)
		sum := int64(0) // sum is stored in us
		for i := 0; i < numTrials; i++ {
			start := time.Now()
			_, err := krawczyk.Split(secretMsg, 5, 2)
			durs[i] = time.Since(start)
			sum += durs[i].Microseconds()
			if err != nil {
				t.Error(err)
			}
		}

		// counting average and std.err (in ms)
		avgDur := float64(sum) / 1000.0 / float64(numTrials)
		stdDev := 0.0
		for i := 0; i < numTrials; i++ {
			stdDev += math.Pow(float64(durs[i].Nanoseconds())/1000000.0-avgDur, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(numTrials))
		stdErr := stdDev / math.Sqrt(float64(numTrials))

		// the results are stored in bytes for size, and ms for svg.time and std.err
		_, err = w.WriteString(fmt.Sprintf("ssms,%d,%.4f,%.4f,%.4f\n", size, avgDur, stdErr, stdDev))
		if err != nil {
			t.Error(err)
		}

		err = w.Flush()
		if err != nil {
			t.Error(err)
		}
	}
}

func TestRSAModeOBF(t *testing.T) {
	// CTR vs OFB vs GCM
	plaintext := make([]byte, 32)
	key := make([]byte, 32)
	block, _ := aes.NewCipher(key)
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	decrypted := make([]byte, len(plaintext))
	block, _ = aes.NewCipher(key)
	stream2 := cipher.NewOFB(block, iv[:])
	stream2.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("not equal %v %v", plaintext, decrypted)
	}
}

func BenchmarkRSAModeOBF(b *testing.B) {
	// CTR vs OFB vs GCM
	plaintext := make([]byte, 1_000_000)
	key := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		block, _ := aes.NewCipher(key)
		var iv [aes.BlockSize]byte
		stream := cipher.NewOFB(block, iv[:])
		ciphertext := make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)
	}
}

func BenchmarkRSAModeCTR(b *testing.B) {
	// CTR vs OFB vs GCM
	plaintext := make([]byte, 1_000_000)
	key := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		block, _ := aes.NewCipher(key)
		var iv [aes.BlockSize]byte
		stream := cipher.NewCTR(block, iv[:])

		ciphertext := make([]byte, len(plaintext))
		stream.XORKeyStream(ciphertext, plaintext)
	}
}

func BenchmarkRSAModeGCM(b *testing.B) {
	// CTR vs OFB vs GCM
	plaintext := make([]byte, 1_000_000)
	key := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		block, _ := aes.NewCipher(key)
		iv := make([]byte, 12)
		stream, _ := cipher.NewGCM(block)
		ciphertext := make([]byte, len(plaintext))
		stream.Seal(ciphertext, iv, plaintext, nil)
	}
}

func TestSplitWithRandomizerAndIncreasingSize(t *testing.T) {
	numTrials := 10000
	sizes := make([]int, 0)
	for size := 10; size < 5_000; size += 10 {
		sizes = append(sizes, size)
	}
	for size := 5_000; size < 200_000; size += 1000 {
		sizes = append(sizes, size)
	}

	f, err := os.Create("data/proc_time_randomizer.csv")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	_, err = w.WriteString("algo,size(bytes),avg_proc_time(ms),std_err(ms),std_dev(ms)\n")
	if err != nil {
		t.Error(err)
	}

	r := csprng.NewCSPRNG()

	// shamir secret sharing
	for s := 0; s < len(sizes); s++ {
		size := sizes[s]
		secretMsg := make([]byte, size)
		_, _ = r.Read(secretMsg)

		runtime.GC()

		// warmups
		for i := 0; i < 10; i++ {
			_, err := shamir.SplitWithRandomizer(secretMsg, 5, 2, r)
			if err != nil {
				t.Error(err)
			}
		}

		durs := make([]time.Duration, numTrials)
		sum := int64(0) // sum is stored in us
		for i := 0; i < numTrials; i++ {
			start := time.Now()
			_, err := shamir.SplitWithRandomizer(secretMsg, 5, 2, r)
			durs[i] = time.Since(start)
			sum += durs[i].Microseconds()
			if err != nil {
				t.Error(err)
			}
		}

		// counting average and std.err (in ms)
		avgDur := float64(sum) / 1000.0 / float64(numTrials)
		stdDev := 0.0
		for i := 0; i < numTrials; i++ {
			stdDev += math.Pow(float64(durs[i].Nanoseconds())/1000000.0-avgDur, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(numTrials))
		stdErr := stdDev / math.Sqrt(float64(numTrials))

		// the results are stored in bytes for size, and ms for svg.time and std.err
		_, err = w.WriteString(fmt.Sprintf("shamir,%d,%.4f,%.4f,%.4f\n", size, avgDur, stdErr, stdDev))
		if err != nil {
			t.Error(err)
		}

		// stop the measurement if the latency is > 1 second
		if avgDur > 1000 {
			break
		}
	}

	// krawczyk secret sharing (ssms)
	for s := 0; s < len(sizes); s++ {
		size := sizes[s]
		secretMsg := make([]byte, size)
		_, _ = r.Read(secretMsg)

		runtime.GC()

		// warmups
		for i := 0; i < 10; i++ {
			_, err := krawczyk.SplitWithRandomizer(secretMsg, 5, 2, r)
			if err != nil {
				t.Error(err)
			}
		}

		durs := make([]time.Duration, numTrials)
		sum := int64(0) // sum is stored in us
		for i := 0; i < numTrials; i++ {
			start := time.Now()
			_, err := krawczyk.SplitWithRandomizer(secretMsg, 5, 2, r)
			durs[i] = time.Since(start)
			sum += durs[i].Microseconds()
			if err != nil {
				t.Error(err)
			}
		}

		// counting average and std.err (in ms)
		avgDur := float64(sum) / 1000.0 / float64(numTrials)
		stdDev := 0.0
		for i := 0; i < numTrials; i++ {
			stdDev += math.Pow(float64(durs[i].Nanoseconds())/1000000.0-avgDur, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(numTrials))
		stdErr := stdDev / math.Sqrt(float64(numTrials))

		// the results are stored in bytes for size, and ms for svg.time and std.err
		_, err = w.WriteString(fmt.Sprintf("ssms,%d,%.4f,%.4f,%.4f\n", size, avgDur, stdErr, stdDev))
		if err != nil {
			t.Error(err)
		}

		err = w.Flush()
		if err != nil {
			t.Error(err)
		}

		// stop the measurement if the latency is > 1 second
		if avgDur > 1000 {
			break
		}
	}
}

func encryptAES(key []byte, plaintext []byte) ([]byte, error){
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCTR(block, iv[:])

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// TestPrivacyPreservingEncoding measure the overhead of
// - shamir secret-sharing
// - secret-sharing made short (SSMS or Krawczyk)
// - symmetric encryption
// - asymmetric encryption
func TestPrivacyPreservingEncoding(t *testing.T) {
	TestSplitWithRandomizerAndIncreasingSize(t)

	numTrials := 10000
	sizes := make([]int, 0)
	for size := 10; size < 5_000; size += 10 {
		sizes = append(sizes, size)
	}
	for size := 5_000; size < 200_000; size += 1000 {
		sizes = append(sizes, size)
	}

	r := csprng.NewCSPRNG()

	f, err := os.OpenFile("data/proc_time_randomizer.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	// symmetric encryption with AES-256
	for s := 0; s < len(sizes); s++ {
		size := sizes[s]
		secretKey := []byte("iniadalahsebuahkatasandirahasia!")
		secretMsg := make([]byte, size)
		_, _ = r.Read(secretMsg)

		runtime.GC()

		// warmups
		for i := 0; i < 10; i++ {
			_, err := encryptAES(secretKey, secretMsg)
			if err != nil {
				t.Error(err)
			}
		}

		// run the actual measurements
		durs := make([]time.Duration, numTrials)
		sum := int64(0) // sum is stored in us
		for i := 0; i < numTrials; i++ {
			start := time.Now()
			_, err := encryptAES(secretKey, secretMsg)
			durs[i] = time.Since(start)
			sum += durs[i].Microseconds()
			if err != nil {
				t.Error(err)
			}
		}

		// counting average and std.err (in ms)
		avgDur := float64(sum) / 1000.0 / float64(numTrials)
		stdDev := 0.0
		for i := 0; i < numTrials; i++ {
			stdDev += math.Pow(float64(durs[i].Nanoseconds())/1000000.0-avgDur, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(numTrials))
		stdErr := stdDev / math.Sqrt(float64(numTrials))

		// the results are stored in bytes for size, and ms for svg.time and std.err
		_, err = w.WriteString(fmt.Sprintf("aes256,%d,%.4f,%.4f,%.4f\n", size, avgDur, stdErr, stdDev))
		if err != nil {
			t.Error(err)
		}

		err = w.Flush()
		if err != nil {
			t.Error(err)
		}

		// stop the measurement if the latency is > 1 second
		if avgDur > 1000 {
			break
		}
	}

	// asymmetric encryption with RSA
	for s := 0; s < len(sizes); s++ {
		size := sizes[s]
		secretMsg := make([]byte, size)
		_, _ = r.Read(secretMsg)

		privateKey, err := rsa.GenerateKey(rand2.Reader, 2048)
		if err != nil {
			t.Error(err)
		}

		runtime.GC()

		// RSA with 2048-bit key can only encrypt up-to 256 bytes
		// source: https://crypto.stackexchange.com/questions/103171/max-message-length-when-encrypting-with-public-key
		// so we split the secretMsg into multiple parts
		partSize := 240
		numParts := len(secretMsg)/partSize + 1

		// warmups
		for i := 0; i < 10; i++ {
			for j := 0; j < numParts; j++ {
				startIdx := j*partSize
				endIdx := (j+1)*partSize + 1
				if endIdx > len(secretMsg) {
					endIdx = len(secretMsg)
				}
				_, err := rsa.EncryptPKCS1v15(rand2.Reader, &privateKey.PublicKey, secretMsg[startIdx:endIdx])
				if err != nil {
					t.Errorf("message size: %d, part: %d, err: %v", len(secretMsg[startIdx:endIdx]), j, err)
				}
			}
		}

		// run the actual measurements
		durs := make([]time.Duration, numTrials)
		sum := int64(0) // sum is stored in us
		for i := 0; i < numTrials; i++ {
			start := time.Now()
			for j := 0; j < numParts; j++ {
				startIdx := j * partSize
				endIdx := (j+1)*partSize + 1
				if endIdx > len(secretMsg) {
					endIdx = len(secretMsg)
				}

				_, err := rsa.EncryptPKCS1v15(rand2.Reader, &privateKey.PublicKey, secretMsg[startIdx:endIdx])
				durs[i] = time.Since(start)
				sum += durs[i].Microseconds()
				if err != nil {
					t.Errorf("message size: %d, part: %d, err: %v", len(secretMsg[startIdx:endIdx]), j, err)
				}

			}
		}

		// counting average and std.err (in ms)
		avgDur := float64(sum) / 1000.0 / float64(numTrials)
		stdDev := 0.0
		for i := 0; i < numTrials; i++ {
			stdDev += math.Pow(float64(durs[i].Nanoseconds())/1000000.0-avgDur, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(numTrials))
		stdErr := stdDev / math.Sqrt(float64(numTrials))

		// the results are stored in bytes for size, and ms for svg.time and std.err
		_, err = w.WriteString(fmt.Sprintf("rsa,%d,%.4f,%.4f,%.4f\n", size, avgDur, stdErr, stdDev))
		if err != nil {
			t.Error(err)
		}

		err = w.Flush()
		if err != nil {
			t.Error(err)
		}

		// stop the measurement if the latency is > 1 second
		if avgDur > 1000 {
			break
		}
	}

}

func TestThroughputAES(t *testing.T) {
	secretKey := []byte("iniadalahsebuahkatasandirahasia!")
	numThreads := runtime.NumCPU()
	numRequest := 1_000_000
	reqSize := 50

	data := make([]byte, reqSize)
	rand.Read(data)
	input := make(chan []byte, 1_000)
	output := make(chan []byte, 1_000)

	for i := 0; i < numThreads; i++ {
		go func() {
			for in := range input {
				res, _ := encryptAES(secretKey, in)
				output <- res
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < numRequest; i++ {
			in := make([]byte, 50)
			copy(in, data)
			input <- in
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRequest; i++ {
			<- output
		}
	}()
	wg.Wait()

	dur := time.Since(start)
	t.Log("#workers ", runtime.NumCPU())
	t.Log("duration ", dur)
	t.Log("throughput ", float64(numRequest)/dur.Seconds(), "req/s")
}

func TestThroughputShamir(t *testing.T) {
	numThreads := runtime.NumCPU()
	numRequest := 1_000_000
	reqSize := 50

	data := make([]byte, reqSize)
	rand.Read(data)
	input := make(chan []byte, 1_000)
	output := make(chan [][]byte, 1_000)

	for i := 0; i < numThreads; i++ {
		go func() {
			r := csprng.NewCSPRNG()
			for in := range input {
				res, _ := shamir.SplitWithRandomizer(in, 4, 2, r)
				output <- res
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < numRequest; i++ {
			in := make([]byte, 50)
			copy(in, data)
			input <- in
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRequest; i++ {
			<- output
		}
	}()
	wg.Wait()

	dur := time.Since(start)
	t.Log("#workers ", runtime.NumCPU())
	t.Log("duration ", dur)
	t.Log("throughput ", float64(numRequest)/dur.Seconds(), "req/s")
}

func TestThroughputSSMS(t *testing.T) {
	numThreads := runtime.NumCPU()
	numRequest := 1_000_000
	reqSize := 50

	data := make([]byte, reqSize)
	rand.Read(data)
	input := make(chan []byte, 1_000)
	output := make(chan [][]byte, 1_000)

	for i := 0; i < numThreads; i++ {
		go func() {
			r := csprng.NewCSPRNG()
			for in := range input {
				res, _ := krawczyk.SplitWithRandomizer(in, 4, 2, r)
				output <- res
			}
		}()
	}

	start := time.Now()
	go func() {
		for i := 0; i < numRequest; i++ {
			in := make([]byte, 50)
			copy(in, data)
			input <- in
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRequest; i++ {
			<- output
		}
	}()
	wg.Wait()

	dur := time.Since(start)
	t.Log("#workers ", runtime.NumCPU())
	t.Log("duration ", dur)
	t.Log("throughput ", float64(numRequest)/dur.Seconds(), "req/s")
}