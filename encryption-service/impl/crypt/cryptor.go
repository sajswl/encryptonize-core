// Copyright 2021 CYBERCRYPT
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
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"

	"encryption-service/interfaces"
)

// Random returns n cryptographically secure random bytes
func Random(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

type AESCryptor struct {
	keyWrap interfaces.KeyWrapperInterface
	crypter *AESCrypter
}

func NewAESCryptor(KEK []byte) (*AESCryptor, error) {
	keyWrap, err := NewKWP(KEK)
	if err != nil {
		return nil, err
	}

	return NewAESCryptorWithKeyWrap(keyWrap), nil
}

func NewAESCryptorWithKeyWrap(keyWrap interfaces.KeyWrapperInterface) *AESCryptor {
	return &AESCryptor{
		keyWrap: keyWrap,
		crypter: &AESCrypter{},
	}
}

func (c *AESCryptor) Encrypt(data, aad []byte) ([]byte, []byte, error) {
	key, err := Random(32)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := c.crypter.Encrypt(data, aad, key)
	if err != nil {
		return nil, nil, err
	}

	wrappedKey, err := c.keyWrap.Wrap(key)
	if err != nil {
		return nil, nil, err
	}

	return wrappedKey, ciphertext, nil
}

func (c *AESCryptor) EncryptWithKey(data, aad, wrappedKey []byte) ([]byte, error) {
	key, err := c.keyWrap.Unwrap(wrappedKey)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	ciphertext, err := c.crypter.Encrypt(data, aad, key)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (c *AESCryptor) Decrypt(wrappedKey, ciphertext, aad []byte) ([]byte, error) {
	key, err := c.keyWrap.Unwrap(wrappedKey)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	data, err := c.crypter.Decrypt(ciphertext, aad, key)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// EncodeAndEncrypt serializes the data, but otherwise behaves like `Encrypt`
func (c *AESCryptor) EncodeAndEncrypt(data interface{}, aad []byte) ([]byte, []byte, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(data); err != nil {
		return nil, nil, err
	}

	dataBytes := buffer.Bytes()
	return c.Encrypt(dataBytes, aad)
}

// DecodeAndDecrypt behaves like `Decrypt` by deserializes the result into `data`
func (c *AESCryptor) DecodeAndDecrypt(data interface{}, wrappedKey, ciphertext, aad []byte) error {
	plaintext, err := c.Decrypt(wrappedKey, ciphertext, aad)
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(bytes.NewReader(plaintext))
	return dec.Decode(data)
}
