package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/rand"
	"strings"
)

// Chapter 6.1
func cryptStreamCipher(textCh, keyCh <-chan byte, result chan<- byte) {
	defer close(result)

	for {
		text, ok1 := <-textCh
		key, ok2 := <-keyCh

		if !ok1 || !ok2 {
			return
		}

		result <- text ^ key
	}
}

// Chapter 5.4
func cryptXOR(plaintext, key []byte) []byte {
	result := make([]byte, len(plaintext))
	for i := range plaintext {
		result[i] = plaintext[i] ^ key[i]
	}
	return result
}

// Chapter 4.3
func cryptCaesar(text string, key int) string {
	final := ""
	for i := range text {
		final += getOffsetChar(rune(text[i]), key)
	}
	return final
}

func decryptCaesar(ciphertext string, key int) string {
	return cryptCaesar(ciphertext, -key)
}

func encryptCaesar(ciphertext string, key int) string {
	return cryptCaesar(ciphertext, key)
}

func getOffsetChar(c rune, offset int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	index := strings.Index(alphabet, string(c))
	if index == -1 {
		return ""
	}
	return string(alphabet[(index+offset)%26])
}

// Chapter 3.5
func findKey(encrypted []byte, decrypted string) ([]byte, error) {
	for i := range int(math.Pow(2, float64(24))) {
		bytes := intToBytes(i)
		attempt := crypt(encrypted, bytes)
		if string(attempt) == decrypted {
			return bytes, nil
		}
	}
	return []byte{}, fmt.Errorf("key not found")
}

// Chapter 1.11
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

// Chapter 1.7
func keyToCipher(key string) (cipher.Block, error) {
	return aes.NewCipher([]byte(key))
}

// Chapter 1.4
func debugEncryptDecrypt(masterKey, iv, password string) (string, string) {
	encrypted := encrypt(password, masterKey, iv)
	decrypted := decrypt(encrypted, masterKey, iv)

	return encrypted, decrypted
}

// Chapter 1.1
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
