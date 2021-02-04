// Copyright 2020 CYBERCRYPT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Interface representing crypto functionality
type CrypterInterface interface {
	Encrypt(plaintext, aad, key []byte) ([]byte, error)
	Decrypt(ciphertext, aad, key []byte) ([]byte, error)
}

type AESCrypter struct {
}

const nonceLength = 12
const tagLength = 16

const Overhead = int(tagLength + nonceLength)

// Random returns n cryptographically secure random bytes
func Random(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// AESGCMEncrypt encrypts and authenticates plaintext and additional data using the standard AES GCM mode
func AESGCMEncrypt(data, aad, nonce, key []byte, tagLen int) error {
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return err
	}

	aesgcm.Seal(data[:0], nonce, data, aad)

	return nil
}

// AESGCMDecrypt decrypties and verifies ciphertext and additional data using the standard AES GCM mode
func AESGCMDecrypt(data, aad, nonce, key []byte, tagLen int) error {
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return err
	}

	_, err = aesgcm.Open(data[:0], nonce, data, aad)

	return err
}

// Encrypt encrypts a plaintext with additional associated data (aad) using the provided key returning the resulting ciphertext.
// The backing array of plaintext is likely modified during this operation.
func (c *AESCrypter) Encrypt(plaintext, aad, key []byte) ([]byte, error) {
	ciphertext := append(plaintext, make([]byte, Overhead)...) // make sure we also have space
	nonce, err := Random(nonceLength)
	if err != nil {
		return nil, err
	}
	copy(ciphertext[len(plaintext)+tagLength:], nonce)

	err = AESGCMEncrypt(ciphertext[:len(plaintext)], aad, nonce, key, tagLength)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt decrypts a ciphertext with additional associated data (aad) using the provided key returning the resulting plaintext.
// ciphertext is modified during this operation.
func (c *AESCrypter) Decrypt(ciphertext, aad, key []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	nonce := ciphertext[len(ciphertext)-nonceLength:]
	err := AESGCMDecrypt(ciphertext[:len(ciphertext)-nonceLength], aad, nonce, key, tagLength)
	if err != nil {
		return nil, err
	}

	return ciphertext[:len(ciphertext)-Overhead], err
}
