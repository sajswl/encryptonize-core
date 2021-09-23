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

// Delete creates a new client and calls Delete through the client
func Delete(userAT, objectID string) error {
	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Delete failed at NewClient"), err)
	}

	// Call Encryptonize and delete the object
	err = client.Delete(objectID)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Delete failed at Delete"), err)
	}

	log.Printf("%v", utils.Pass("Successfully deleted object!\n"))

	return nil
}
