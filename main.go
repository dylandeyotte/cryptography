package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
)

// Chapter 9.1
func decryptAES(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return cipher.AEAD.Open(gcm, nil, nonce, ciphertext, nil)
}

func encryptDES(key, plaintext []byte) ([]byte, error) {
	// Create Block
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Pad message
	padded := padMsg(plaintext, block.BlockSize())

	// Creat encrypted slice
	encrypted := make([]byte, len(padded)+block.BlockSize())

	// Allocate iv at beginning of encrypted
	// iv must be block size
	// fill iv
	iv := encrypted[:block.BlockSize()]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, errors.New("invalid iv size")
	}

	// Encrypt from end of iv
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(encrypted[block.BlockSize():], padded)

	return encrypted, nil
}

func padMsg(plaintext []byte, blockSize int) []byte {
	index := len(plaintext) - (len(plaintext) % blockSize)
	lastBlock := padWithZerosDES(plaintext[index:], blockSize)
	fullBlocks := plaintext[:index]
	return append(fullBlocks, lastBlock...)
}

// Chapter 8.1
func feistel(msg []byte, roundKeys [][]byte) []byte {
	midpoint := len(msg) / 2
	lhs := msg[:midpoint]
	rhs := msg[midpoint:]

	for _, round := range roundKeys {
		nrhs := xor(lhs, hash(rhs, round, len(lhs)))
		lhs = rhs
		rhs = nrhs
	}
	return append(rhs, lhs...)
}

// Chapter 7.8
func deriveRoundKey(masterKey [4]byte, roundNumber int) [4]byte {
	for i, j := range masterKey {
		masterKey[i] = j ^ byte(roundNumber)
	}
	return masterKey
}

// Chapter 7.4
func padWithZeros(block []byte, desiredSize int) []byte {
	for {
		if len(block) == desiredSize {
			return block
		}
		block = append(block, 0)
	}
	// OR return append(block, make([]byte, desiredSize-len(block))...)
}

// Chapter 7.1
func getBlockSize(keyLen, cipherType int) (int, error) {
	buf := make([]byte, keyLen)
	switch cipherType {
	case typeAES:
		block, err := aes.NewCipher(buf)
		if err != nil {
			return 0, err
		}
		return block.BlockSize(), nil
	case typeDES:
		block, err := des.NewCipher(buf)
		if err != nil {
			return 0, err
		}
		return block.BlockSize(), nil
	default:
		return 0, errors.New("invalid cipher type")
	}
}

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
/*func generateRandomKey(length int) (string, error) {
	randReader := rand.New(rand.NewSource(0))
	buf := make([]byte, length)
	_, err := randReader.Read(buf)
	if err != nil {
		return "", err
	}
	hex := fmt.Sprintf("%x", buf)
	return hex, nil
}*/

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
