package csprng

import (
	"github.com/starius/aesctrat"
	"math/rand"
	"time"
)

type CSPRNG struct {
	c  *aesctrat.AesCtr
	iv []byte
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func NewCSPRNG() *CSPRNG {
	keyIv := make([]byte, 32)
	rand.Read(keyIv)
	ctr := aesctrat.NewAesCtr(keyIv[:16])
	return &CSPRNG{ctr, keyIv[16:]}
}

func NewCSPRNGWithKeyIV(keyIv []byte) *CSPRNG {
	ctr := aesctrat.NewAesCtr(keyIv[:16])
	return &CSPRNG{ctr, keyIv[16:]}
}

func (r *CSPRNG) Read(buff []byte) (int, error) {
	r.c.XORKeyStreamAt(buff, buff, r.iv, 0)
	return len(buff), nil
}

// Perm produces byte array of length n that contains
// unique random between 0 and n-1 (inclusive) or [0,n)
func (r *CSPRNG) Perm(n byte) []byte {
	buff := make([]byte, n)
	for i := byte(0); i < n; i++ {
		buff[i] = i
	}
	shuffler := make([]byte, n)
	_, _ = r.Read(shuffler)
	for i := byte(0); i < n-2; i++ {
		j := 1 + shuffler[i] % (n-i)
		temp := buff[i]
		buff[i] = buff[j]
		buff[j] = temp
	}
	return buff
}

// GetUniqueBytes produces n unique byte. If n >= 20, this uses Perm(255)
// and return the first n bytes. Assuming PRNG that produces uniform number
// when n >= 20, the chance of producing duplicate byte is greater than 50%,
// that is why Perm(255) is used.
// For more information, please see https://en.wikipedia.org/wiki/Birthday_problem.
func (r *CSPRNG) GetUniqueBytes(n byte) []byte {
	if n >= 20 {
		return r.Perm(255)[:n]
	}
	buff := make([]byte, n)
	isExist := map[byte]bool{}
	_, _ = r.Read(buff)
	for i := byte(0); i < n; i++ {
		isDuplicate := true
		for isDuplicate {
			if _, exist := isExist[buff[i]]; !exist {
				isDuplicate = false
				break
			}
			_, _ = r.Read(buff[i:i+1])
		}
		isExist[buff[i]] = true
	}
	return buff
}