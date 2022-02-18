package randomizer

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
)

type Randomizer struct {
	c cipher.Stream
}

func NewRandomizer() *Randomizer {
	keyAndIV := make([]byte, 16 + aes.BlockSize)
	rand.Read(keyAndIV)
	c, err := aes.NewCipher(keyAndIV[:16])
	if err != nil {
		panic(err)
	}
	s := cipher.NewCTR(c, keyAndIV[16:])
	return &Randomizer{c: s}
}

func (r *Randomizer) Read(buff []byte) (int, error) {
	r.c.XORKeyStream(buff, buff)
	return len(buff), nil
}

func (r *Randomizer) Perm(n byte) []byte {
	buff := make([]byte, n)
	for i := byte(0); i < n; i++ {
		buff[i] = i
	}
	shuffler := make([]byte, n)
	_, _ = r.Read(shuffler)
	max := n-1
	for i := byte(0); i < n-1; i++ {
		rx := shuffler[i]%max
		temp := buff[rx]
		buff[max] = temp
		max--
	}
	return buff
}