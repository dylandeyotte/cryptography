package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"math"
	"math/big"
	"math/bits"
	"strings"
)

// Chapter 13.10
func createECDSAMessage(message string, privateKey *ecdsa.PrivateKey) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash.Sum(nil))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v.%x", message, signature), nil
}

// Chapter 13.7
func hmac(message, key string) string {
	// Split key
	first := key[:len(key)/2]
	second := key[len(key)/2:]

	// Hash second half key with message
	hash := sha256.New()
	hash.Write([]byte(second + message))
	hashSecondAndMsg := hash.Sum(nil)

	// First half key into bytes
	allByte := []byte(first)

	// Concatenate first half with hashed second half and key
	allByte = append(allByte, hashSecondAndMsg...)

	// Hash all
	hash2 := sha256.New()
	hash2.Write([]byte(allByte))
	hashSecond := hash2.Sum(nil)

	return fmt.Sprintf("%x", hashSecond)
}

// Chapter 13.4
func macMatches(message, key, checksum string) bool {
	message += key
	h := sha256.New()
	h.Write([]byte(message))
	return checksum == fmt.Sprintf("%x", h.Sum(nil))
}

// Chapter 13.1
func checksumMatches(message string, checksum string) bool {
	hash := sha256.New()
	hash.Write([]byte(message))
	return checksum == fmt.Sprintf("%x", hash.Sum(nil))
}

// Chapter 12.10
func hashFunc(input []byte) [4]byte {
	rotated := []uint8{}
	shifted := []byte{}
	var final [4]byte
	for _, b := range input {
		rotated = append(rotated, bits.RotateLeft8(uint8(b), 3))
	}
	for _, n := range rotated {
		shifted = append(shifted, byte(n)<<2)
	}
	for i, bt := range shifted {
		final[i%4] = bt ^ final[i%4]
	}
	return final
}

// Chapter 12.1
type hasher struct {
	hash hash.Hash
}

func newHasher() *hasher {
	newHash := sha256.New()
	return &hasher{
		hash: newHash,
	}
}

func (h *hasher) Write(s string) (int, error) {
	return h.hash.Write([]byte(s))
}

func (h *hasher) GetHex() string {
	s := h.hash.Sum(nil)
	return hex.EncodeToString(s)
}

// Chapter 11.15
// c = message d = private key n = mod
func decryptRSA(c, d, n *big.Int) *big.Int {
	return new(big.Int).Exp(c, d, n)
}

// Chapter 11.14
// d = private key
func getD(e, tot *big.Int) *big.Int {
	return new(big.Int).ModInverse(e, tot)
}

// Chapter 11.11
// m = message e = public key exponent n = public key modulus
func encryptionFormula(m, e, n *big.Int) *big.Int {
	return new(big.Int).Exp(m, e, n)
}

// Chapter 11.6
func getTot(p, q *big.Int) *big.Int {
	tot := new(big.Int)
	newP := p.Sub(p, big.NewInt(1))
	newq := q.Sub(q, big.NewInt(1))
	return tot.Mul(newP, newq)
}

func getE(tot *big.Int) *big.Int {
	totMinusTwo := new(big.Int).Sub(tot, big.NewInt(2))

	e, _ := rand.Int(randReader, totMinusTwo)
	e.Add(e, big.NewInt(2))

	for gcd(e, tot).Cmp(big.NewInt(1)) != 0 {
		e, _ = rand.Int(randReader, totMinusTwo)
		e.Add(e, big.NewInt(2))
	}
	return e
}

// Chapter 11.5
func generatePrivateNums(keysize int) (*big.Int, *big.Int) {
	p, _ := getBigPrime(keysize)
	q, _ := getBigPrime(keysize)
	return p, q
}

func getN(p, q *big.Int) *big.Int {
	n := new(big.Int)
	return n.Mul(p, q)
}

// Chapter 11.1
func encryptRSA(pubKey *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, msg, nil)
}

// Chapter 10.1
func genKeys() (pubKey *ecdsa.PublicKey, privKey *ecdsa.PrivateKey, err error) {
	curve := elliptic.P256()
	privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey = &privKey.PublicKey
	return pubKey, privKey, nil
}

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
		nrhs := xor(lhs, hashxor(rhs, round, len(lhs)))
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
