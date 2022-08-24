package cryptolib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	maxPlainTextSizeBytes = 2 ^ 24 //arbitrary maximum, this is a string encryption library, not file encryption.
	keySizeBytes          = 32     //expected key size for AES256
	saltSizeBytes         = 9      //chosen to base64 doesn't have an '='. 2^96 * 2^72 = 2^168 -> 2^56 encryptions possible with the same key
	ciphertextPartsNumber = 5      //$2a$salt$nonce$ciphertext
	gcmNonceSizeBytes     = 12     //96 bits is NIST standard
)

//Encrypt up to 2^68 strings using the same Key without issue.
//It doesn't encrypt more than 16MB strings.
//authenticatedData is strongly desired, it usually is the entity identifiers owner of what's being encrypted.
func Encrypt(key []byte, plaintext string, authenticatedData string) (string, error) {

	err := validateEncryptionInputs(key, plaintext, authenticatedData)
	if err != nil {
		return "", err
	}

	plaintextBinary := []byte(plaintext)
	authenticatedDataBinary := []byte(authenticatedData)

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce, err := GenerateRandomBytes(gcmNonceSizeBytes)
	if err != nil {
		return "", err
	}

	dKey, salt, err := deriveKey(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintextBinary, authenticatedDataBinary)

	output := fmt.Sprintf("$a1$%s$%s$%s", base64.URLEncoding.EncodeToString([]byte(salt)), base64.URLEncoding.EncodeToString([]byte(nonce)), base64.URLEncoding.EncodeToString([]byte(ciphertext)))

	return output, nil
}

type cipherTextType struct {
	format           string
	salt             []byte
	nonce            []byte
	ciphertextBinary []byte
}

//Decrypt ciphertexts generated with the Library Encrypt.
func Decrypt(key []byte, ciphertext string, authenticatedData string) (string, error) {

	cipherTextStruct, err := decodeCiphertext(ciphertext)
	if err != nil {
		return "", err
	}

	dKey := deriveKeyFromSalt(key, cipherTextStruct.salt)

	block, err := aes.NewCipher(dKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	authenticatedDataBinary := []byte(authenticatedData)

	plaintext, err := aesgcm.Open(nil, cipherTextStruct.nonce, cipherTextStruct.ciphertextBinary, authenticatedDataBinary)
	if err != nil {
		return "", fmt.Errorf("cryptolib: Decrypt error: %s", err)
	}

	return string(plaintext[:]), nil

}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n uint) ([]byte, error) {

	if n < 1 {
		return nil, fmt.Errorf("cryptoLib: requested number of random bytes lower than 1")
	}

	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func init() {
	//TODO check if a temp file exists "cryptolib_init_2018-10-18"
	// if it doesn't call all get entropy from services and create the file
	// if it does, just call get local entropy.
	// goal is to not call the entropy services each time the init is called
	// this might prevent lag, in service restart, running testing several times a day, and in AWS Lambda, testing and other use cases.

	addLocalEntropyToRandomPool()

	//Should not run while doing tests, it's disabled for the moment.
	//_ = AddEntropyToRandomPool()
}

//AddEntropyToRandomPool is called when the package is imported. It can be called at any time without any impact
func AddEntropyToRandomPool() error {

	randomData, err := getEntropyFromKMS()
	if err != nil {
		randomData, err = getEntropyFromUbuntuPollinate()
		if err != nil {
			randomData, err = getEntropyFromRandomService()
		}
	}
	if err != nil {
		return errors.New("All random services failed")
	}
	writeToEntropyPool(randomData)
	if err != nil {
		return err
	}
	return nil
}

//EncryptWithSearch returns encrypted text and searchKey. The same plaintext will always give the same searchKey independent of authenticatedData
func EncryptWithSearch(key []byte, plaintext string, authenticatedData string) (ciphertext string, searchKey string, err error) {

	encryptionKey, hmacKey, err := stretch256Key(key)
	if err != nil {
		return "", "", err
	}

	ciphertext, err = Encrypt(encryptionKey, plaintext, authenticatedData)
	if err != nil {
		return "", "", err
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(plaintext))
	searchKey = base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return ciphertext, searchKey, nil

}

//GetSearchKey given the key and the plainttextSearchKey the function provides the searchable Key.
func GetSearchKey(key []byte, plaintextSearchKey string) (string, error) {
	_, hmacKey, err := stretch256Key(key)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(plaintextSearchKey))
	searchKey := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return searchKey, nil
}
