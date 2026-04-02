package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

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
