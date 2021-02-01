package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func encryptFileCBC(input io.Reader, output io.Writer, bc cipher.Block, iv []byte) error {
	EncBuf := make([]byte, 16)
	EncryptedBuf := make([]byte, 16)
	r := bufio.NewReaderSize(input, 1024*1024*20)
	w := bufio.NewWriterSize(output, 1024*1024*20)
	defer w.Flush()
	for {
		n, err := r.Read(EncBuf)
		if err == io.EOF {
			EncBuf = make([]byte, 16)
			io.ReadFull(rand.Reader, EncBuf)
			EncBuf[15] = 16
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			bc.Encrypt(EncryptedBuf, EncBuf)
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
			break
		}
		if err != nil {
			return err
		}
		if n == 16 {
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			bc.Encrypt(EncryptedBuf, EncBuf)
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
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
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			bc.Encrypt(EncryptedBuf, EncBuf)
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
			break
		}
	}
	return nil
}

var errWrongSize = errors.New("Weong Size")

func decryptFileCBC(input io.Reader, output io.Writer, bc cipher.Block, iv []byte) error {
	r := bufio.NewReaderSize(input, 1024*1024*20)
	w := bufio.NewWriterSize(output, 1024*1024*20)
	defer w.Flush()
	Buf := make([]byte, 16)
	lastBuf := make([]byte, 16)
	isStart := true
	for {
		n, err := r.Read(Buf)
		if err == io.EOF {
			if lastBuf[15] < 16 {
				w.Write(lastBuf[0 : 16-int(lastBuf[15])])
				break
			} else if lastBuf[15] == 16 {
				break
			} else {
				return errWrongSize
			}
		}
		if err != nil {
			return err
		}
		if n != 16 {
			return errWrongSize
		}
		if !isStart {
			w.Write(lastBuf)
		}
		bc.Decrypt(lastBuf, Buf)
		for i := range lastBuf {
			lastBuf[i] = lastBuf[i] ^ iv[i]
		}
		copy(iv, Buf)
		if isStart {
			isStart = false
		}
	}
	return nil
}
