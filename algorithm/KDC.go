// KnightChaser's Key Distribution Center simulation implementation written in Go
// Due to the poor support for external libraries in C/C++, I decided to use Go for this part of the project
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Hexify converts a string to a hex string
func Hexify(data []byte) string {
	hexString := ""
	for _, char := range data {
		hexString += fmt.Sprintf("%02x", char)
	}
	return hexString
}

// Encrypt the given BYTE type array with the given key
func EncryptAESCTR(key []byte, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// Decrypt the given BYTE type array with the given key
func DecryptAESCTR(key []byte, ciphertext []byte) []byte {
	// AES-CTR decryption is the same as encryption
	decrypted := EncryptAESCTR(key, ciphertext)
	return decrypted
}

func main() {
	var keyEncryptionKeyUserA [16]byte
	var keyEncryptionKeyUserB [16]byte
	var kdcSessionKey [16]byte

	// First, we need to generate a random key for the KDC. KDC already has UserA and UserB's key encryption keys
	// Create a cryptographic key with random package
	rand.Read(keyEncryptionKeyUserA[:])
	rand.Read(keyEncryptionKeyUserB[:])
	rand.Read(kdcSessionKey[:])
	fmt.Printf("[KDC ← UserA] kekUserA                : %v\n", Hexify(keyEncryptionKeyUserA[:]))
	fmt.Printf("[KDC ← UserB] kekUserB                : %v\n", Hexify(keyEncryptionKeyUserB[:]))
	fmt.Printf("[KDC]         kdcSessionKey           : %v\n", Hexify(kdcSessionKey[:]))

	// Second, we need to encrypt the KDC session key with the key encryption keys of UserA and UserB
	kekUserAEncryptedKDCSessionKey := EncryptAESCTR(keyEncryptionKeyUserA[:], kdcSessionKey[:])
	kekUserBEncryptedKDCSessionKey := EncryptAESCTR(keyEncryptionKeyUserB[:], kdcSessionKey[:])
	fmt.Printf("[KDC → UserA] Encrypted kdcSessionKey : %v\n", Hexify(kekUserAEncryptedKDCSessionKey))
	fmt.Printf("[KDC → UserB] Encrypted kdcSessionKey : %v\n", Hexify(kekUserBEncryptedKDCSessionKey))

	// Third, each user needs to decrypt the KDC session key with their key encryption keys
	kekUserADecryptedKDCSessionKey := DecryptAESCTR(keyEncryptionKeyUserA[:], kekUserAEncryptedKDCSessionKey)
	kekUserBDecryptedKDCSessionKey := DecryptAESCTR(keyEncryptionKeyUserB[:], kekUserBEncryptedKDCSessionKey)
	fmt.Printf("[UserA]       Decrypted kdcSessionKey : %v\n", Hexify(kekUserADecryptedKDCSessionKey))
	fmt.Printf("[UserB]       Decrypted kdcSessionKey : %v\n", Hexify(kekUserBDecryptedKDCSessionKey))

	// Finally, we need to check if the decrypted KDC session keys are the same.
	// If they are, then the KDC session key is successfully distributed to both users.
	if bytes.Compare(kekUserADecryptedKDCSessionKey, kekUserBDecryptedKDCSessionKey) == 0 {
		fmt.Println("[UserA ↔ UserB] ** KDC session key successfully distributed to both users **")
	} else {
		fmt.Println("** KDC session key distribution failed **")
	}

}
