package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
)

// Chapter 11.6
func gcd(x, y *big.Int) *big.Int {
	xCopy := new(big.Int).Set(x)
	yCopy := new(big.Int).Set(y)
	for yCopy.Cmp(big.NewInt(0)) != 0 {
		xCopy, yCopy = yCopy, xCopy.Mod(xCopy, yCopy)
	}
	return xCopy
}

// Chapter 11.5
func firstNDigits(n big.Int, numDigits int) string {
	if len(n.String()) < numDigits {
		return fmt.Sprintf("%v", n.String())
	}
	return fmt.Sprintf("%v...", n.String()[:numDigits])
}

var randReader = mrand.New(mrand.NewSource(0))

func getBigPrime(bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, errors.New("prime size must be at least 2-bit")
	}
	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}
	bytes := make([]byte, (bits+7)/8)
	p := new(big.Int)
	for {
		if _, err := io.ReadFull(randReader, bytes); err != nil {
			return nil, err
		}
		bytes[0] &= uint8(int(1<<b) - 1)
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		bytes[len(bytes)-1] |= 1
		p.SetBytes(bytes)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// Chapter 9.1
func encryptAES(key, plaintext, nonce []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Chapter 8.5
func decryptDES(key, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < des.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:des.BlockSize]
	ciphertext = ciphertext[des.BlockSize:]
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func padWithZerosDES(block []byte, desiredSize int) []byte {
	for len(block) < desiredSize {
		block = append(block, 0)
	}
	return block
}

// Chapter 7.1
const (
	typeAES = iota
	typeDES
)

// Chapter 8.1
func xor(lhs, rhs []byte) []byte {
	res := []byte{}
	for i := range lhs {
		res = append(res, lhs[i]^rhs[i])
	}
	return res
}

// outputLength should be equal to or less than the length
// of the left half when used in feistel so that the XOR
// has sufficient bytes to operate on
func hashxor(first, second []byte, outputLength int) []byte {
	h := sha256.New()
	h.Write(append(first, second...))
	return h.Sum(nil)[:outputLength]
}

// Chapter 7.1
func getCipherTypeName(cipherType int) string {
	switch cipherType {
	case typeAES:
		return "AES"
	case typeDES:
		return "DES"
	}
	return "unknown"
}

// Chapter 6.1
func encryptStreamCipher(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) != len(key) {
		return nil, errors.New("plaintext and key must be the same length")
	}

	plaintextCh := make(chan byte)
	keyCh := make(chan byte)
	result := make(chan byte)

	go func() {
		defer close(plaintextCh)
		for _, v := range plaintext {
			plaintextCh <- v
		}
	}()

	go func() {
		defer close(keyCh)
		for _, v := range key {
			keyCh <- v
		}
	}()

	go cryptStreamCipher(plaintextCh, keyCh, result)

	res := []byte{}
	for v := range result {
		res = append(res, v)
	}
	return res, nil
}

func decryptStreamCipher(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) != len(key) {
		return nil, errors.New("ciphertext and key must be the same length")
	}

	ciphertextCh := make(chan byte)
	keyCh := make(chan byte)
	result := make(chan byte)

	go func() {
		defer close(ciphertextCh)
		for _, v := range ciphertext {
			ciphertextCh <- v
		}
	}()

	go func() {
		defer close(keyCh)
		for _, v := range key {
			keyCh <- v
		}
	}()

	go cryptStreamCipher(ciphertextCh, keyCh, result)

	res := []byte{}
	for v := range result {
		res = append(res, v)
	}
	return res, nil
}

// Chapter 3.5
func crypt(dat, key []byte) []byte {
	final := []byte{}
	for i, d := range dat {
		final = append(final, d^key[i])
	}
	return final
}

func intToBytes(num int) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, int64(num))
	if err != nil {
		return nil
	}
	bs := buf.Bytes()
	if len(bs) > 3 {
		return bs[:3]
	}
	return bs
}
