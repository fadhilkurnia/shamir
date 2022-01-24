package krawczyk

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/fadhilkurnia/shamir/shamir"
	"github.com/klauspost/reedsolomon"
)

// key size: 16 bytes (128 bit)
// data len type: uint16 (2 bytes), support up to 65 KB secret data

const LenKey = 16
const LenLen = 2

func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) > 65536 {
		return nil, fmt.Errorf(
			"the provided secret is to large, we can only split up to %d bytes data", 65536)
	}
	if threshold == 0 || parts == 0 {
		return nil, errors.New("#parts and #threshold can not be zero")
	}
	if threshold > parts {
		return nil, fmt.Errorf(
			"threshold should be less to the number of parts, #parts=%d $threshold=%d", parts, threshold)
	}

	// generate random key
	key := make([]byte, LenKey)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret key: %v", err)
	}

	// encrypt the secret
	encryptedSecret, err := encrypt(secret, key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes: %v", err)
	}

	// encode the encrypted secret (ciphertext) with reed-solomon
	encoder, err := reedsolomon.New(parts-threshold, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize reed-solomon encoder: %v", err)
	}
	encodedSecret, err := encoder.Split(encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the secret: %v", err)
	}

	// secret-share the key & len with shamir's secret-sharing
	// the resulting metadata share, each is 16 bytes (key) + 2 bytes (length) + 1 bytes (ss metadata) = 19 bytes
	lenSecret := uint16(len(encryptedSecret))
	lenSecretBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenSecretBytes, lenSecret)
	keyLenPair := append(key, lenSecretBytes...)
	ssKeyLenPair, err := shamir.Split(keyLenPair, parts, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to secret-shares the key and len: %v", err)
	}

	// combine the encoded data and the metadata share (key & length)
	lenEncodedSecret := len(encodedSecret[0])
	lenEncodedMetadata := len(ssKeyLenPair[0])
	results := make([][]byte, parts)
	for i := 0; i < parts; i++ {
		results[i] = make([]byte, lenEncodedMetadata+lenEncodedSecret)
		j := 0
		for j < lenEncodedMetadata {
			results[i][j] = ssKeyLenPair[i][j]
			j += 1
		}
		for j < lenEncodedMetadata+lenEncodedSecret {
			results[i][j] = encodedSecret[i][j-lenEncodedMetadata]
			j += 1
		}
	}

	return results, nil
}

func Combine(ssData [][]byte, parts, threshold int) ([]byte, error) {
	if len(ssData[0]) > 65536 {
		return nil, fmt.Errorf(
			"the provided secret is to large, we can only combine up to %d bytes data", 65536)
	}
	if threshold == 0 || parts == 0 {
		return nil, errors.New("#parts and #threshold can not be zero")
	}
	if threshold > parts {
		return nil, fmt.Errorf(
			"threshold should be less to the number of parts, #parts=%d $threshold=%d", parts, threshold)
	}

	// split encoded data and secret-shared metadata
	secretStartIdx := LenKey + LenLen + 1
	encodedData := make([][]byte, len(ssData))
	ssMetadata := make([][]byte, len(ssData))
	for i := 0; i < len(ssData); i++ {
		ssMetadata[i] = ssData[i][:secretStartIdx]
		encodedData[i] = ssData[i][secretStartIdx:]
	}

	// get the metadata
	metadata, err := shamir.Combine(ssMetadata)
	if err != nil {
		fmt.Println("failed to retrieve the metadata: ", err)
		return nil, err
	}
	key := metadata[:LenKey]
	length := binary.LittleEndian.Uint16(metadata[LenKey:])

	// decode the ciphertext
	decoder, err := reedsolomon.New(parts-threshold, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize reed-solomon decoder: %v", err)
	}
	var ciphertextBuffer bytes.Buffer
	err = decoder.Join(&ciphertextBuffer, encodedData, int(length))
	if err != nil {
		return nil, fmt.Errorf("failed to decode the data: %v", err)
	}

	// decrypt the ciphertext with the key
	secret, err := decrypt(ciphertextBuffer.Bytes(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the decoded ciphertext: %v", err)
	}

	return secret, nil
}
