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