package main

import (
	"encoding/hex"
	"fmt"

	"code.hq.twilio.com/skantorowicz/encryption-library/crypto_library"
)

func main() {
	err := cryptolib.AddEntropyToRandomPool()
	fmt.Println(err)
	//cryptolib.GetEntropyFromUbuntuPollinate()
	return
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574") //correct key

	//key, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	//key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f2061207365637265") //short key
	plaintext := "user secret"
	authenticatedData := "user id"

	ciphertext, searchKey, err := cryptolib.EncryptWithSearch(key, plaintext, authenticatedData)
	fmt.Printf("%s\n", ciphertext)
	fmt.Printf("%s\n", searchKey)

	return
	ciphertext, err = cryptolib.Encrypt(key, plaintext, authenticatedData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", ciphertext)

	decryptedciphertext, err := cryptolib.Decrypt(key, ciphertext, authenticatedData)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", decryptedciphertext)

}
