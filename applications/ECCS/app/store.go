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
	"errors"
	"io"
	"log"
	"os"

	"eccs/utils"
)

// openFile loads a file into memory
func openFile(filename string) []byte {
	dat, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Store failed"), err)
	}
	return dat
}

// reads bytes from provided filename, or from stdin
// exits program if both are provided
func readInput(filename string, stdin bool) ([]byte, error) {
	var plaintext []byte

	if filename != "" && stdin {
		return nil, errors.New("can't take both filename and stdin")
	}
	if filename != "" {
		plaintext = openFile(filename)
	}
	if stdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		plaintext = data
	}

	return plaintext, nil
}

// Store creates a new client and calls Store through the client
func Store(userAT, filename, associatedData string, stdin bool) error {
	//Determine whether to read data from file or stdin
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Store failed"), err)
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Store failed"), err)
	}
	// Call Encryptonize and store the object
	out, err := client.Store(plaintext, []byte(associatedData))
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Store failed"), err)
	}

	// Give back the object id to the user
	log.Printf("%vObjectID: %v", utils.Pass("Successfully stored object!\n"), out)

	return nil
}
