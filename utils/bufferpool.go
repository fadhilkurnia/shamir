package utils

import (
	"bytes"
	"runtime"
)

type BytesBufferPool struct {
	ch chan *bytes.Buffer
}

func NewBytesBufferPool(size int)  *BytesBufferPool {
	if size <= 0 {
		size = runtime.NumCPU() * 1024
	}
	return &BytesBufferPool{
		ch: make(chan *bytes.Buffer, size),
	}
}

func (b *BytesBufferPool) Get() *bytes.Buffer {
	select {
	case bb := <- b.ch:
		return bb
	default:
		return &bytes.Buffer{}
	}
}

func (b *BytesBufferPool) Put(bb *bytes.Buffer)  {
	select {
	case b.ch <- bb:
		return
	default:
	//	do nothing and do not block, the buffered channel is full
	//  we discard the *bytes.Buffer
	}
}
