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
	"fmt"
	"io"
	"log"
	"os"

	"encoding/json"
)

type EncryptOutput struct {
	Ciphertext     string `json:"ciphertext"`
	ObjectID       string `json:"oid"`
	AssociatedData string `json:"aad"`
}

func Encrypt(userAT, filename, associatedData string, stdin bool) error {
	var plaintext []byte
	var err error

	//Determine whether to read data from file or stdin
	if filename != "" && stdin {
		log.Fatalf("%v: can't take both filename and stdin", utils.Fail("Store failed"))
	}
	if filename != "" {
		plaintext = openFile(filename)
	}
	if stdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("%v: %v", utils.Fail("Encrypt failed"), err)
		}
		plaintext = data
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Encrypt failed"), err)
	}

	// Call Encryptonize and encrypt the object
	oid, ciphertext, aad, err := client.Encrypt(plaintext, []byte(associatedData))
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Encrypt failed"), err)
	}

	enc := &EncryptOutput{
		Ciphertext:     b64.StdEncoding.EncodeToString(ciphertext),
		AssociatedData: b64.StdEncoding.EncodeToString(aad),
		ObjectID:       oid,
	}

	jsonOutput, err := json.MarshalIndent(enc, "", "    ")
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Formatting output as JSON failed!"), err)
	}

	// Log status to logging output
	log.Printf("%v\n", utils.Pass("Successfully encrypted object!"))

	// Output actual output to stdout
	fmt.Printf("%s\n", jsonOutput)

	return nil
}
