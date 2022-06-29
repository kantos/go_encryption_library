package cryptolib

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := "user secret"
	authenticatedData := "user id"

	ciphertext, err := Encrypt(key, plaintext, authenticatedData)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		return
	}
	ciphertextParts := strings.Split(ciphertext, "$")
	if len(ciphertextParts) != ciphertextPartsNumber {
		t.Errorf("expected: %d, got %d parts", ciphertextPartsNumber, len(ciphertextParts))
	}
}

func TestDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	expectedPlaintext := "user secret"
	authenticatedData := "user id"
	cipherText := "$a1$a_l_bKQhDZBz$13xHCHCmXXSwgQbo$vs8yN1_eHF1R0vluvW82CeZzyvVY7VJZSXEW"

	plaintext, err := Decrypt(key, cipherText, authenticatedData)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		return
	}

	if strings.Compare(plaintext, expectedPlaintext) != 0 {
		t.Errorf("expected: %s, got %s plaintext", expectedPlaintext, plaintext)
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	authenticatedData := "user id"
	cipherText := "$a1$a_l_bKQhDZBz$13xHCHCmXXSwgQbo$ws8yN1_eHF1R0vluvW82CeZzyvVY7VJZSXEW"

	_, err := Decrypt(key, cipherText, authenticatedData)
	if err == nil {
		t.Error("Unexpected error")
	}

	if err.Error() != "cryptolib: Decrypt error: cipher: message authentication failed" {
		t.Error("Error mismatch")
	}
}

func TestAddEntropyToRandomPool(t *testing.T) {
	err := AddEntropyToRandomPool()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := "user secret"
	authenticatedData := "user id"

	ciphertext, err := Encrypt(key, plaintext, authenticatedData)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		return
	}

	decryptedPlaintext, err := Decrypt(key, ciphertext, authenticatedData)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	if strings.Compare(plaintext, decryptedPlaintext) != 0 {
		t.Errorf("expected: %s, got %s plaintext", plaintext, decryptedPlaintext)
	}

}

func TestEncryptWithSearch(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := "user secret"
	authenticatedData := "user id"

	ciphertext, searchKey, err := EncryptWithSearch(key, plaintext, authenticatedData)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
		return
	}

	ciphertextParts := strings.Split(ciphertext, "$")
	if len(ciphertextParts) != ciphertextPartsNumber {
		t.Errorf("expected: %d, got %d parts", ciphertextPartsNumber, len(ciphertextParts))
	}
	if strings.Compare(searchKey, "QHfHCJjcBDOv_rIUiW_75xA0p-GS9dQ7Loam4Gcg0_M=") != 0 {
		t.Error("searchKey doesn't match expectedSearchKey")
	}
}

func TestGetSearchKey(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //right key
	searchKey, err := GetSearchKey(key, "user secret")
	if err != nil {
		t.Errorf("Unexpected error %s", err.Error())
	}
	fmt.Println("2")

	if strings.Compare(searchKey, "QHfHCJjcBDOv_rIUiW_75xA0p-GS9dQ7Loam4Gcg0_M=") != 0 {
		t.Error("searchKey doesn't match")
	}
}
