package krawczyk

import (
	"bytes"
	"fmt"
	"github.com/klauspost/reedsolomon"
	"math/rand"
	"reflect"
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

func TestSplitCombine(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog.")

	shares, err := Split(secretMsg, 4, 2)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}
	combinedShares, err := Combine(shares[2:], 4, 2)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestSplitCombine2(t *testing.T) {
	secretMsg := []byte("The quick brown fox jumps over the lazy dog.")

	shares, err := Split(secretMsg, 4, 2)
	if err != nil {
		fmt.Printf("failed to split the message: %v", err)
	}
	shares[1] = nil
	shares[3] = nil
	combinedShares, err := Combine(shares, 4, 2)
	if err != nil {
		fmt.Printf("failed to combine the message: %v", err)
	}

	t.Logf("original len: %d, encoded len: %d", len(secretMsg), len(shares[0]))

	isEqual := reflect.DeepEqual(secretMsg, combinedShares)
	if !isEqual {
		t.Errorf("The combined secret is different. Expected: '%v', but got '%v'.\n", string(secretMsg), string(combinedShares))
	}
}

func TestReedSolomonSplit(t *testing.T) {
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