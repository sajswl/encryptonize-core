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
	"encoding/json"
	"log"

	"eccs/utils"
)

type RetrievedData struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associatedData"` //TODO: change to associated_data (encryptonize core api)
}

type DecodedRetrievedData struct {
	Plaintext      string `json:"plaintext"`
	AssociatedData string `json:"associated_data"`
}

// Retrieve creates a new client and calls Retrieve through the client
func Retrieve(userAT, oid string) error {
	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Retrieve failed"), err)
	}

	// Call Encryptonize and retrieve object
	response, err := client.Retrieve(oid)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("Retrieve failed"), err)
	}

	var data RetrievedData
	err = json.Unmarshal([]byte(response), &data)
	if err != nil {
		log.Fatalf("Provided input does not contain the required structure!")
	}

	retrieved, err := json.Marshal(DecodedRetrievedData{Plaintext: string(data.Plaintext), AssociatedData: string(data.AssociatedData)})

	log.Printf("%v\n%s", utils.Pass("Successfully retrieved object!"), retrieved)

	return nil
}
