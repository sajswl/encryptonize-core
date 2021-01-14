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

package app

import (
	"log"

	"eccs/utils"
)

// Retrieve creates a new client and calls Retrieve through the client
func Retrieve(userAT, oid string) error {
	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Retrieve failed"), err)
	}

	// Call Encryptonize and retrieve object
	out, err := client.Retrieve(oid)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Retrieve failed"), err)
	}

	// Print object back to user
	log.Printf("%vObject: %v", utils.Pass("Successfully retrieved object!\n"), out)

	return nil
}
