package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math/big"
)

func GenerateState() string {
	b := make([]byte, 32)  // create a 32-byte slice
	_, err := rand.Read(b) // read b variable and fill it with secure random bytes
	if err != nil {
		log.Fatalf("Failed to generate state: %v", err)
	}

	return base64.URLEncoding.EncodeToString(b)
}

func GenerateSHA256Hash(value string) string {
	data := sha256.New()
	data.Write([]byte(value))
	hashedValue := data.Sum(nil)

	hashedValueHex := hex.EncodeToString(hashedValue)

	return hashedValueHex
}

func GenerateVerificationCode(length int) (string, error) {
	digits := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, length)

	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[index.Int64()]
	}

	return string(code), nil
}
