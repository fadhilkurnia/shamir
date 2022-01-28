package shamir

import (
	hcShamir "github.com/hashicorp/vault/shamir"
	"math/rand"
	"reflect"
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