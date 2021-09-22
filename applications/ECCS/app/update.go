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
	"log"

	"eccs/utils"
)

// Update creates a new client and calls Update through the client
func Update(userAT, objectID, filename, associatedData string, stdin bool) error {
	//Determine whether to read data from file or stdin
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Update failed at readInput"), err)
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Update failed at NewClient"), err)
	}

	// Call Encryptonize and update the object
	err = client.Update(objectID, plaintext, []byte(associatedData))
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Update failed at Update"), err)
	}

	return nil
}
