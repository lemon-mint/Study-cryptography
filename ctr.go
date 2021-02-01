package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

//12 byte nonce required
func encryptFileCTR(input io.Reader, output io.Writer, bc cipher.Block, nonce []byte) error {
	EncBuf := make([]byte, 16)
	EncryptedBuf := make([]byte, 16)
	nonceBuf := make([]byte, 16)
	copy(nonceBuf[:12], nonce[:12])
	r := bufio.NewReaderSize(input, 1024*1024*20)
	w := bufio.NewWriterSize(output, 1024*1024*20)
	defer w.Flush()
	var counter uint32
	for {
		n, err := r.Read(EncBuf)
		binary.BigEndian.PutUint32(nonceBuf[12:16], counter)
		if err == io.EOF {
			EncBuf = make([]byte, 16)
			io.ReadFull(rand.Reader, EncBuf)
			EncBuf[15] = 16
			bc.Encrypt(EncryptedBuf, nonceBuf)
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ EncryptedBuf[i]
			}
			w.Write(EncBuf)
			break
		}
		if err != nil {
			return err
		}
		if n == 16 {
			bc.Encrypt(EncryptedBuf, nonceBuf)
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ EncryptedBuf[i]
			}
			w.Write(EncBuf)
		} else {
			randbuf := make([]byte, 16)
			tmp := make([]byte, n)
			copy(tmp, EncBuf)
			EncBuf = make([]byte, 16)
			copy(EncBuf, tmp)
			io.ReadFull(rand.Reader, randbuf)
			for i := n; i < 16; i++ {
				EncBuf[i] = randbuf[i]
			}
			EncBuf[15] = byte(16 - n)
			bc.Encrypt(EncryptedBuf, nonceBuf)
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ EncryptedBuf[i]
			}
			w.Write(EncryptedBuf)
			break
		}
		counter++
	}
	return nil
}
