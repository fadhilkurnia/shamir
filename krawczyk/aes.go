package krawczyk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
)

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	var out bytes.Buffer
	writer := &cipher.StreamWriter{S: stream, W: &out}
	if _, err := io.Copy(writer, bytes.NewReader(plaintext)); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	var out bytes.Buffer
	reader := &cipher.StreamReader{S: stream, R: bytes.NewReader(ciphertext)}
	if _, err := io.Copy(&out, reader); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}
