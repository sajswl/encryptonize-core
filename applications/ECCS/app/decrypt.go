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

package app

import (
	"eccs/utils"
	b64 "encoding/base64"
	"encoding/json"
	"log"
)

func Decrypt(userAT, filename string, stdin bool) error {
	var enc EncryptedData
	storedData, err := readInput(filename, stdin)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Decrypt failed"), err)
	}

	err = json.Unmarshal(storedData, &enc)
	if err != nil {
		log.Fatalf("Provided input does not contain the required structure!")
	}

	decodedCiphertext, err := b64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		log.Fatalf("Failed to decode ciphertext")
	}

	decodedAAD, err := b64.StdEncoding.DecodeString(enc.AssociatedData)
	if err != nil {
		log.Fatalf("Failed to decode associated data")
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Decrypt failed"), err)
	}

	// Call Encryptonize and decrypt object
	m, aad, err := client.Decrypt(enc.ObjectID, decodedCiphertext, decodedAAD)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Retrieve failed"), err)
	}

	// Print object back to user
	log.Printf("%vObject: m=\"%s\", aad=\"%s\"", utils.Pass("Successfully decrypted object!\n"), string(m), string(aad))

	return nil
}
