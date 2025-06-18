package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func GenerateUsername(baseName string) (string, error) {
	clean := strings.ReplaceAll(baseName, " ", "")
	if len(clean) == 0 {
		return "", errors.New("base name cannot be empty")
	}

	name := strings.ToLower(clean) // normalize
	var prefix string

	if len(name) < 5 {
		prefix = name
	} else {
		prefix = name[:5] // take first 5 characters
	}

	// Ensure total length does not exceed 44
	maxSuffixLen := 40 - len(prefix)
	suffix, err := generateRandomAlphanumeric(maxSuffixLen)
	if err != nil {
		return "", err
	}

	return prefix + suffix, nil
}

func generateRandomAlphanumeric(length int) (string, error) {
	result := make([]byte, length)

	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}

	return string(result), nil
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

func GenerateRandomPasswordChar20() (string, error) {
	result := make([]byte, 20)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range result {
		num, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}
