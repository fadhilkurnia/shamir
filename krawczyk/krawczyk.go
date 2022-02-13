package krawczyk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/fadhilkurnia/shamir/shamir"
	"github.com/klauspost/reedsolomon"
	"math"
	"math/rand"
)

// key size: 16 bytes (128 bit)
// data len type: uint16 (2 bytes), support up to 65 KB secret data

const LenKey = 24
const LenLen = 2

func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) > math.MaxUint16 {
		return nil, fmt.Errorf(
			"the provided secret is to large, we can only split up to %d bytes data", math.MaxUint16)
	}
	if threshold == 0 || parts == 0 {
		return nil, errors.New("#parts and #threshold can not be zero")
	}
	if threshold > parts {
		return nil, fmt.Errorf(
			"threshold should be less to the number of parts, #parts=%d $threshold=%d", parts, threshold)
	}
	if threshold > 255 || parts > 255 {
		return nil, fmt.Errorf(
			"#parts and #threshold should be less than 256, #parts=%d $threshold=%d", parts, threshold)
	}

	// if N == K, use shamir's secret sharing instead to avoid additional storage.
	if parts == threshold {
		return shamir.Split(secret, parts, threshold)
	}

	// handle if parts-threshold=0 => making data parts = 0 that cause error in reed-solomon
	// we make data parts = 1 in this case
	originalParts := parts
	if parts-threshold == 0 {
		parts += 1
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
	if err := encoder.Encode(encodedSecret); err != nil {
		return nil, fmt.Errorf("failed to encode the secret: %v", err)
	}
	// append part-id in the encoded data
	for i := 0; i < len(encodedSecret); i++ {
		encodedSecret[i] = append(encodedSecret[i], byte(i))
	}

	// handle if parts-threshold == 0, previously we add one temporary part
	// for erasure coding, we need to remove it now
	if originalParts != parts {
		encodedSecret = encodedSecret[:len(encodedSecret)-1]
		parts = originalParts
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
	results := newByteMatrix(parts, lenEncodedSecret+lenEncodedMetadata)
	for i := 0; i < parts; i++ {
		copy(results[i][0:lenEncodedMetadata], ssKeyLenPair[i])
		copy(results[i][lenEncodedMetadata:], encodedSecret[i])
	}

	return results, nil
}

// SplitWithRandomizer is exactly the same with Split but with randomizer provided by the caller
func SplitWithRandomizer(secret []byte, parts, threshold int, randomizer *rand.Rand) ([][]byte, error) {
	if len(secret) > math.MaxUint16 {
		return nil, fmt.Errorf(
			"the provided secret is to large, we can only split up to %d bytes data", math.MaxUint16)
	}
	if threshold == 0 || parts == 0 {
		return nil, errors.New("#parts and #threshold can not be zero")
	}
	if threshold > parts {
		return nil, fmt.Errorf(
			"threshold should be less to the number of parts, #parts=%d $threshold=%d", parts, threshold)
	}
	if threshold > 255 || parts > 255 {
		return nil, fmt.Errorf(
			"#parts and #threshold should be less than 256, #parts=%d $threshold=%d", parts, threshold)
	}

	// if N == K, use shamir's secret sharing instead to avoid additional storage.
	if parts == threshold {
		return shamir.SplitWithRandomizer(secret, parts, threshold, randomizer)
	}

	// handle if parts-threshold=0 => making data parts = 0 that cause error in reed-solomon
	// we make data parts = 1 in this case
	originalParts := parts
	if parts-threshold == 0 {
		parts += 1
	}

	// generate random key
	key := make([]byte, LenKey)
	_, err := randomizer.Read(key)
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
	if err := encoder.Encode(encodedSecret); err != nil {
		return nil, fmt.Errorf("failed to encode the secret: %v", err)
	}
	// append part-id in the encoded data
	for i := 0; i < len(encodedSecret); i++ {
		encodedSecret[i] = append(encodedSecret[i], byte(i))
	}

	// handle if parts-threshold == 0, previously we add one temporary part
	// for erasure coding, we need to remove it now
	if originalParts != parts {
		encodedSecret = encodedSecret[:len(encodedSecret)-1]
		parts = originalParts
	}

	// secret-share the key & len with shamir's secret-sharing
	// the resulting metadata share, each is 16 bytes (key) + 2 bytes (length) + 1 bytes (ss metadata) = 19 bytes
	lenSecret := uint16(len(encryptedSecret))
	lenSecretBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenSecretBytes, lenSecret)
	keyLenPair := append(key, lenSecretBytes...)
	ssKeyLenPair, err := shamir.SplitWithRandomizer(keyLenPair, parts, threshold, randomizer)
	if err != nil {
		return nil, fmt.Errorf("failed to secret-shares the key and len: %v", err)
	}

	// combine the encoded data and the metadata share (key & length)
	lenEncodedSecret := len(encodedSecret[0])
	lenEncodedMetadata := len(ssKeyLenPair[0])
	results := newByteMatrix(parts, lenEncodedSecret+lenEncodedMetadata)
	for i := 0; i < parts; i++ {
		copy(results[i][0:lenEncodedMetadata], ssKeyLenPair[i])
		copy(results[i][lenEncodedMetadata:], encodedSecret[i])
	}

	return results, nil
}

func newByteMatrix(r, c int) [][]byte {
	a := make([]uint8, r*c)
	m := make([][]uint8, r)
	lo, hi := 0, c
	for i := range m {
		m[i] = a[lo:hi:hi]
		lo, hi = hi, hi+c
	}
	return m
}

func Combine(ssData [][]byte, parts, threshold int) ([]byte, error) {
	if len(ssData[0]) > math.MaxUint16 {
		return nil, fmt.Errorf(
			"the provided secret is to large, we can only combine up to %d bytes data", math.MaxUint16)
	}
	if threshold == 0 || parts == 0 {
		return nil, errors.New("#parts and #threshold can not be zero")
	}
	if threshold > parts {
		return nil, fmt.Errorf(
			"threshold should be less to the number of parts, #parts=%d $threshold=%d", parts, threshold)
	}
	if threshold > 255 || parts > 255 {
		return nil, fmt.Errorf(
			"#parts and #threshold should be less than 256, #parts=%d $threshold=%d", parts, threshold)
	}

	// if N == K, use shamir's secret sharing instead to avoid additional storage.
	if parts == threshold {
		return shamir.Combine(ssData)
	}

	// remove empty shares
	numCleanParts := 0
	for i := 0; i < len(ssData); i++ {
		if ssData[i] != nil {
			numCleanParts++
		}
	}
	if numCleanParts != len(ssData) {
		cleanSSData := make([][]byte, numCleanParts)
		j := 0
		for i := 0; i < len(ssData); i++ {
			if ssData[i] == nil {
				continue
			}
			cleanSSData[j] = ssData[i]
			j++
		}
		ssData = cleanSSData
	}

	// handle if parts-threshold == 0 which require additional temporary part
	if parts-threshold == 0 {
		parts += 1
	}

	// split encoded data and secret-shared metadata
	secretStartIdx := LenKey + LenLen + 1
	encodedData := make([][]byte, parts)
	ssMetadata := make([][]byte, len(ssData))
	for i := 0; i < len(ssData); i++ {
		ssMetadata[i] = ssData[i][:secretStartIdx]

		// check the part-id of the reed-solomon encoded data
		partID := ssData[i][len(ssData[i])-1]
		if partID > byte(parts) {
			return nil, errors.New("the given secret-shared data is wrong, part-id should be less than the number of parts")
		}
		encodedData[ssData[i][len(ssData[i])-1]] = ssData[i][secretStartIdx : len(ssData[i])-1]
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
	if err = decoder.ReconstructData(encodedData); err != nil {
		return nil, fmt.Errorf("failed to reconstruct data: %v", err)
	}
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
