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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	if len(os.Args) == 2 {
		enc()
	} else if len(os.Args) == 3 && os.Args[2] == "decrypt" {
		dec()
	}
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
		/*data = []byte(`-----BEGIN RSA PUBLIC KEY-----
		MIICCgKCAgEAta/CWvk9Y36OCYPtpxi9VplMsCF4FLD1XxyGdzwmyda6l+mipS0A
		IDZKduLLzktf9KPhQVgQ6TstGyZg1YAAccxWjwx4RifWMfJlfk6ZbMh+9KxkjYo0
		PlFmhm/4hsWmfKUH46uOGxzc9jAI/nurmwlrE8fW17uDw5NE0RDqVxL+ktnD81mH
		8qReuR78WRyoE2p38krwXLhhp0UAtDQd9cyexmbhrCMFnLrg2p6+sxRkhUPgFRMo
		s57l8aHnArtTYpcnebUvx+QSB9iW5tWekGvh1HUKyOXselLMuofP/+SC9j4yGnew
		s64q220BQYAWIN+7VaT6Rnuofd8uv+sZkiZ+hPSpiOSq1hRhekXCyzysqZF11oFm
		vkxq6XsJxOosMHVqJcK5A/GkyHE/pCBFordpFDLsFnd1EvjLpYcROX9zQCmTjHyK
		UfN/w1fCfWEX3Ln+9Expxd5NssC8vEdwARPYOXGVEHDrTDdB4IZ9OGkQn2DFOUq3
		SVbCf7bLvmFvQMwdkmRZGm1Avgqc9PDijSwiOCr75hRCIA3tHKce+rHxJAFGsF6B
		cRbb3Nn08DeyCLupOOL+dOeqTu0n1cVG1tA3nmpGH3azamk3GOJONAq2fWroUUA5
		5K4bxT74KUNbbChnwr4ta3ASB+e6EH/T7UVwhB64bVn8c/ZwbEwj6LECAwEAAQ==
		-----END RSA PUBLIC KEY-----`)*/
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
		io.ReadFull(rand.Reader, keyinfo)
		io.ReadFull(rand.Reader, ivkey)
		w.Sync()
	} else {
		fmt.Println("usage: <filename>")
	}
}

func dec() {
	if len(os.Args) == 3 {
		keyf, err := os.Open("privkey.pem")
		if err != nil {
			genkeypair()
			keyf, err = os.Open("privkey.pem")
			if err != nil {
				return
			}
		}
		data, err := ioutil.ReadAll(keyf)
		block, _ := pem.Decode(data)
		pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		//fmt.Println(err)
		file, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Println("file open error")
			return
		}
		w, err := os.OpenFile(os.Args[1][:len(os.Args[1])-len(".encrypted")], os.O_CREATE, os.ModeAppend)
		if err != nil {
			fmt.Println("file open error")
			return
		}
		size := make([]byte, 8)
		file.Read(size)
		encryptedivkey := make([]byte, 512)
		file.Read(encryptedivkey)
		keyinfo, err := rsa.DecryptOAEP(sha3.New384(), rand.Reader, pub, encryptedivkey, []byte{})
		if err != nil {
			fmt.Println("key error")
			return
		}
		cipher, err := aes.NewCipher(keyinfo[16:])
		if err != nil {
			fmt.Println("aes error")
			return
		}
		decryptFileCBC(file, w, cipher, keyinfo[:16])
		io.ReadFull(rand.Reader, keyinfo)
		w.Sync()
	} else {
		fmt.Println("usage: <filename> <mode>")
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
