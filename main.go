package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/fadhilkurnia/shamir/shamir"
	"io"
	"log"
	"time"
)

const DEBUG = false

func main() {
	msg := "A quick brown fox jumped over the lazy dog.aaaaaaaaaaaaaaaaaaaaa"
	repetition := 1000
	msgLenMax := 32768

	checkSecretSharing(msg, 4, 2)
	measureSecretSharingLatency(msg, msgLenMax, repetition)
	measureEncryptionLatency(msg, msgLenMax, repetition)
}

func checkSecretSharing(msg string, part, threshold int) {
	shares, err := shamir.Split([]byte(msg), part, threshold)
	if err != nil {
		log.Fatalf("Failed to secret share the message: %v\n", err)
	}
	if DEBUG {
		fmt.Println("secret sharing result: ", shares)
	}

	origMsg, err := shamir.Combine(shares)
	if err != nil {
		log.Fatalf("failed to reconstruct secret")
	}
	fmt.Println(msg)
	fmt.Println(string(origMsg))
}

// Measuring shamir secret sharing
func measureSecretSharingLatency(initMsg string, msgLenMax, repetition int) {
	msg := initMsg
	msgLen := len(msg)
	for msgLen <= msgLenMax {
		startTime := time.Now()
		for i:=0; i < repetition; i++ {
			shares, err := shamir.Split([]byte(msg), 4, 2)
			if err != nil {
				log.Fatalf("Failed to secret share the message: %v\n", err)
			}
			if DEBUG {
				fmt.Println("secret sharing result: ", shares)
			}
		}
		duration := time.Since(startTime)
		fmt.Printf("%d - Secret sharing duration %v (%f ns per operation)\n", msgLen, duration, float64(duration.Nanoseconds())/float64(repetition))

		msg = msg + msg
		msgLen = len(msg)
	}
}

// Measuring AES encryption
func measureEncryptionLatency(initMsg string, msgLenMax, repetition int) {
	encryptionKey := "0123456789012345"
	msg := initMsg
	msgLen := len(msg)
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		log.Fatalf("Failed to initialize aes cipher: %v\n", err)
	}
	for msgLen <= msgLenMax {
		startTime := time.Now()
		for i:=0; i < repetition; i++ {
			cipherText := make([]byte, aes.BlockSize+len(msg))
			iv := cipherText[:aes.BlockSize]
			if _, err = io.ReadFull(rand.Reader, iv); err != nil {
				return
			}
			stream := cipher.NewCFBEncrypter(block, iv)
			stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(msg))
			if DEBUG {
				fmt.Println("aes result: ", cipherText)
			}
		}
		duration := time.Since(startTime)
		fmt.Printf("%d - AES encryption duration %v (%f ns per operation)\n", msgLen, duration, float64(duration.Nanoseconds())/float64(repetition))

		msg = msg + msg
		msgLen = len(msg)
	}
}