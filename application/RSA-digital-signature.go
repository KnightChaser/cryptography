// KnightChaser's RSA-Based digital signature implementation written in Go
// Due to the poor support for external libraries in C/C++, I decided to use Go for this part of the project
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
)

// GenerateKeyPair generates an RSA key pair.
func GenerateRSAKeyPair(keyLengthInByte int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLengthInByte)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// SignMessage creates a digital signature for the given message using the private key.
func SignMessage(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(message)
	fmt.Printf("[Sender] Hash       : %x (you signed)\n", hashed[:])
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifySignature checks if the given signature is valid for the message using the public key.
func VerifySignature(message []byte, signature []byte, publicKey *rsa.PublicKey) bool {
	hashed := sha256.Sum256(message)
	fmt.Printf("[Public] Hash       : %x (being verifeid)\n", hashed[:])
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		log.Panic("Error verifying signature:", err)
	}
	return err == nil
}

func main() {
	// Generate RSA key pair
	keyLengthInByte := 2048
	privateKey, publicKey, err := GenerateRSAKeyPair(keyLengthInByte)
	if err != nil {
		log.Panic("Error generating key pair:", err)
		return
	}

	// Message to be signed
	message := []byte("OwO Digital Signature (with RSA)!")

	fmt.Printf("[Sender] Message    : %s\n", message)
	fmt.Printf("[Sender] Private Key: D => %v, E => %v\n", privateKey.D, privateKey.E)
	fmt.Printf("[Public] Public Key : N => %v, E => %v\n", publicKey.N, publicKey.E)

	// Sign the message with the private key
	signature, err := SignMessage(message, privateKey)
	if err != nil {
		log.Panic("Error signing message:", err)
		return
	}

	// Digital signature doesn't encrypt the message, it just signs it.
	// To provide confidentiality, the message must be encrypted with a symmetric key. (e.g. digital envelope)

	// Verify the signature with the public key
	if VerifySignature(message, signature, publicKey) {
		fmt.Println("[Public] Signature is valid because the hash values are the same.")
	} else {
		fmt.Println("[Public] Signature is invalid because the hash values are different.")
	}
}
