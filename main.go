package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
)

// Mine
func debugEncryptDecrypt(masterKey, iv, password string) (string, string) {
	encrypted := encrypt(password, masterKey, iv)
	decrypted := decrypt(encrypted, masterKey, iv)

	return encrypted, decrypted
}

func keyToCipher(key string) (cipher.Block, error) {
	return aes.NewCipher([]byte(key))
}

func generateRandomKey(length int) (string, error) {
	randReader := rand.New(rand.NewSource(0))
	buf := make([]byte, length)
	_, err := randReader.Read(buf)
	if err != nil {
		return "", err
	}
	hex := fmt.Sprintf("%x", buf)
	return hex, nil
}

// Boot Dev
func encrypt(plainText, key, iv string) string {
	bytes := []byte(plainText)
	blockCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Println(err)
		return ""
	}
	stream := cipher.NewCTR(blockCipher, []byte(iv))
	stream.XORKeyStream(bytes, bytes)
	return fmt.Sprintf("%x", bytes)
}

func decrypt(cipherText, key, iv string) string {
	blockCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Println(err)
		return ""
	}
	stream := cipher.NewCTR(blockCipher, []byte(iv))
	bytes, err := hex.DecodeString(cipherText)
	if err != nil {
		log.Println(err)
		return ""
	}
	stream.XORKeyStream(bytes, bytes)
	return string(bytes)
}
