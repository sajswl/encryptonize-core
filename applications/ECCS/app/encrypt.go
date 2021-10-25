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
	"fmt"
	"log"

	"eccs/utils"
)

type EncryptedData struct {
	Ciphertext     string `json:"ciphertext"`
	AssociatedData string `json:"associatedData"`
	ObjectID       string `json:"objectId"`
}

func Encrypt(userAT, filename, associatedData string, stdin bool) error {
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Encrypt failed"), err)
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Encrypt failed"), err)
	}

	// Call Encryptonize and encrypt the object
	response, err := client.Encrypt(plaintext, []byte(associatedData))
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Encrypt failed"), err)
	}

	// Log status to logging output
	log.Printf("%v\n", utils.Pass("Successfully encrypted object!"))

	// Output actual output to stdout
	fmt.Printf("%s\n", response)

	return nil
}
