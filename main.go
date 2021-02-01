package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	enc()
}

func enc() {
	if len(os.Args) == 2 {
		keyf, err := os.Open("pubkey.pem")
		if err != nil {
			genkeypair()
			keyf, err = os.Open("pubkey.pem")
			if err != nil {
				return
			}
		}
		data, err := ioutil.ReadAll(keyf)
		block, _ := pem.Decode(data)
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		//fmt.Println(err)
		ivkey := make([]byte, 16+32)
		io.ReadFull(rand.Reader, ivkey)
		keyinfo, err := rsa.EncryptOAEP(sha3.New384(), rand.Reader, pub, ivkey, []byte{})
		file, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Println("file open error")
			return
		}
		w, err := os.OpenFile(os.Args[1]+".encrypted", os.O_CREATE, os.ModeAppend)
		if err != nil {
			fmt.Println("file open error")
			return
		}
		size := make([]byte, 8)
		binary.BigEndian.PutUint64(size, uint64(len(keyinfo)))
		w.Write(size)
		w.Write(keyinfo)
		cipher, err := aes.NewCipher(ivkey[16:])
		if err != nil {
			fmt.Println("aes error")
			return
		}
		encryptFileCBC(file, w, cipher, ivkey[:16])
		w.Sync()
	} else {
		fmt.Println("usage: <filename>")
	}
}

func genkeypair() {
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	f, _ := os.OpenFile("privkey.pem", os.O_CREATE, os.ModeAppend)
	pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	f.Close()
	f, _ = os.OpenFile("pubkey.pem", os.O_CREATE, os.ModeAppend)
	pem.Encode(f, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})
	f.Close()
}

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
