package cryptolib

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func validateEncryptionInputs(key []byte, plaintext string, authenticateData string) error {

	// >16MB should use other type of encryption schemes and storage.
	if len(plaintext) > maxPlainTextSizeBytes || len(authenticateData) > maxPlainTextSizeBytes {
		return fmt.Errorf("cryptolib: Plaintext or authenticated data exceeds maximum size %d", maxPlainTextSizeBytes)
	}

	if len(plaintext) < 1 {
		return errors.New("Empty plain text")
	}

	//Check Key size
	if len(key) != keySizeBytes {
		return fmt.Errorf("cryptolib: Key is not of proper size: %d", keySizeBytes)
	}

	//Check key is not initialized
	if bytes.Equal(key, make([]byte, 32)) {
		return errors.New("cryptolib: Key is not initialized")
	}

	return nil
}

func deriveKey(key []byte) (dKey []byte, salt []byte, err error) {

	salt, err = GenerateRandomBytes(saltSizeBytes)
	if err != nil {
		return nil, nil, err
	}

	dKey = deriveKeyFromSalt(key, salt)
	return dKey, salt, nil
}

func deriveKeyFromSalt(key []byte, salt []byte) (dKey []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(salt)
	dKey = mac.Sum(nil)
	return dKey
}

func decodeCiphertext(ciphertext string) (cipherTextType, error) {

	ciphertextParts := strings.Split(ciphertext, "$")

	if len(ciphertextParts) != ciphertextPartsNumber {
		return cipherTextType{}, errors.New("cryptolib: Decrypt: Invalid ciphertext")
	}

	var err error

	cipherText := cipherTextType{}
	cipherText.format = ciphertextParts[1]

	cipherText.salt, err = base64.URLEncoding.DecodeString(ciphertextParts[2])
	if err != nil {
		return cipherTextType{}, fmt.Errorf("cryptolib: Decrypt: %s", err)
	}

	cipherText.nonce, err = base64.URLEncoding.DecodeString(ciphertextParts[3])
	if err != nil {
		return cipherTextType{}, fmt.Errorf("cryptolib: Decrypt: %s", err)
	}

	cipherText.ciphertextBinary, err = base64.URLEncoding.DecodeString(ciphertextParts[4])
	if err != nil {
		return cipherTextType{}, fmt.Errorf("cryptolib: Decrypt: %s", err)
	}

	if strings.Compare(cipherText.format, "a1") != 0 {
		return cipherTextType{}, errors.New("cryptolib: Decrypt: Format not supported")
	}

	return cipherText, nil

}

//stretchKey Given a key, it generates 2 of 256 bits each.
//Only 256 bits key accepted to prevent misuse.
func stretch256Key(key []byte) (encryptionKey []byte, hmacKey []byte, err error) {

	if len(key) != 32 { //32*8 = 256 bits, expected per the name of the function.
		return nil, nil, fmt.Errorf("cryptolib: Key is not of proper size: 256 bits")
	}
	sha512 := sha512.New()
	sha512.Write(key)
	encryptionKey = sha512.Sum(nil)[:32]
	hmacKey = sha512.Sum(nil)[32:]
	return encryptionKey, hmacKey, nil
}
