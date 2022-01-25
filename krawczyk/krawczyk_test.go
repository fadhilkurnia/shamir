package krawczyk

import (
	"bytes"
	"fmt"
	"github.com/klauspost/reedsolomon"
	"reflect"
	"testing"
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

func TestReedSolomonSplitCombine(t *testing.T) {
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