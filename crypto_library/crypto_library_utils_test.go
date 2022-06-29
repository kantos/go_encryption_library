package cryptolib

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestValidateEncryptionInputs(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	plaintext := make([]byte, maxPlainTextSizeBytes-1)
	err := validateEncryptionInputs(key, string(plaintext), "test")
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
}

func TestValidateEncryptionInputsPlainTextMaxSizeExceeded(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	plaintext := make([]byte, maxPlainTextSizeBytes+1)
	err := validateEncryptionInputs(key, string(plaintext), "")
	if err == nil {
		t.Error("Unexpected error")
	}
	if err.Error() != fmt.Sprintf("cryptolib: Plaintext or authenticated data exceeds maximum size %d", maxPlainTextSizeBytes) {
		t.Error("Error mismatch")
	}
}

func TestValidateEncryptionInputsAuthenticatedDataMaxSizeExceeded(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	authenticatedData := make([]byte, maxPlainTextSizeBytes+1)
	err := validateEncryptionInputs(key, "test", string(authenticatedData))
	if err == nil {
		t.Error("Unexpected error")
	}
	if err.Error() != fmt.Sprintf("cryptolib: Plaintext or authenticated data exceeds maximum size %d", maxPlainTextSizeBytes) {
		t.Error("Error mismatch")
	}
}

func TestValidateEncryptionInputsPlainTextEmpty(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	err := validateEncryptionInputs(key, "", "")
	if err == nil {
		t.Error("Unexpected error")
	}
	if err.Error() != "Empty plain text" {
		t.Error("Error mismatch")
	}
}

func TestValidateEncryptionInputsShortKeySize(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f2061207365637265") //short key
	err := validateEncryptionInputs(key, "plaintext", "")
	if err == nil {
		t.Error("Unexpected error")
	}
	if err.Error() != fmt.Sprintf("cryptolib: Key is not of proper size: %d", keySizeBytes) {
		t.Error("Error mismatch")
	}
}

func TestValidateEncryptionInputsLongKeySize(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f20612073656372657482") //long key
	err := validateEncryptionInputs(key, "plaintext", "")
	if err == nil {
		t.Error("Unexpected error")
	}
	if err.Error() != fmt.Sprintf("cryptolib: Key is not of proper size: %d", keySizeBytes) {
		t.Error("Error mismatch")
	}
}

func TestValidateEncryptionInputsNullKey(t *testing.T) {

	key := make([]byte, keySizeBytes)
	err := validateEncryptionInputs(key, "plaintext", "")
	if err == nil {
		t.Error("Unexpected error")
	}
	if err.Error() != "cryptolib: Key is not initialized" {
		t.Error("Error mismatch")
	}
}

func TestDeriveKey(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	dKey, salt, err := deriveKey(key)
	if err != nil {
		t.Errorf("deriveKey failed: %s", err.Error())
	}
	if len(dKey) != keySizeBytes {
		t.Errorf("dKey has invalid size: %d", len(dKey))
	}
	if len(salt) != saltSizeBytes {
		t.Errorf("salt has invalid size: %d", len(salt))
	}
	if bytes.Compare(dKey, key) == 0 {
		t.Error("Derived key must be different from Key")
	}
}

func TestDeriveKeyFromSalt(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	salt, _ := hex.DecodeString("398549819823983478")
	dKey := deriveKeyFromSalt(key, salt)
	precomputedDkey, _ := hex.DecodeString("2c38dadbed7ca76210c23755e7715d7c7476f3d1a00f9d635c96f46cdb04b1cd")

	if bytes.Compare(dKey, precomputedDkey) != 0 {
		t.Error("dKey doesn't match")
	}
}

func TestDecodeCiphertext(t *testing.T) {
	ciphertextFormatted := "$a1$a_l_bKQhDZBz$13xHCHCmXXSwgQbo$vs8yN1_eHF1R0vluvW82CeZzyvVY7VJZSXEW"
	ciphertext, err := decodeCiphertext(ciphertextFormatted)
	if err != nil {
		t.Errorf("decodeCiphertext failed: %s", err.Error())
	}
	expectedCiphertext, _ := base64.URLEncoding.DecodeString("vs8yN1_eHF1R0vluvW82CeZzyvVY7VJZSXEW")
	if bytes.Compare(ciphertext.ciphertextBinary, expectedCiphertext) != 0 {
		t.Error("decodeCiphertext failed")
	}

}

func TestGetEntropyFromRandomService(t *testing.T) {
	random, err := getEntropyFromRandomService()
	if err != nil {
		t.Error("getEntropyFromRandomService failed")
		return
	}
	if len(random) != 21 {
		t.Errorf("getEntropyFromRandomService returns less than 20 characters: %s", random)
	}
}

func TestStretch256Key(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	expectedEncryptionKey, _ := hex.DecodeString("43384c069608e62ed86982ff4170614b3f2b069b902cccbfd32edef768a8589b")
	expectedHmacKey, _ := hex.DecodeString("049e62dd6b20466591ef711ded45ccbf4d6ee4fdce849ae4b873044efb012a5e")
	encryptionKey, hmacKey, _ := stretch256Key(key)

	if bytes.Compare(encryptionKey, expectedEncryptionKey) != 0 {
		t.Error("encryptionKey doesn't match")

	}

	if bytes.Compare(hmacKey, expectedHmacKey) != 0 {
		t.Error("hmacKey doesn't match")
	}

}

func TestStretch256KeyInvalidKeySize(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f2061207365637265") //short key
	_, _, err := stretch256Key(key)

	if err == nil {
		t.Error("Unexpected error")
	}
	if strings.Compare(err.Error(), "cryptolib: Key is not of proper size: 256 bits") != 0 {
		t.Error("Error mismatch")
	}

}

func TestGetEntropyFromUbuntuPollinate(t *testing.T) {
	entropy, err := getEntropyFromUbuntuPollinate()
	if err != nil {
		t.Error("getEntropyFromUbuntuPollinate failed")
	}
	if len(entropy) != 64 {
		t.Errorf("was expecting 64 bytes, got %d", len(entropy))
	}

}

func TestGetInstanceDataEntropy(t *testing.T) {
	lowEntropy := getInstanceDataEntropy()
	if len(lowEntropy) != 64 {
		t.Errorf("was expecting 64 byte hash, got %d", len(lowEntropy))
	}
}
