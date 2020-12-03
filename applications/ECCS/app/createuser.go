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

// Creates a new client and calls CreateUser through the client
func CreateUser(userID, userAT, userKindString string) error {
	var userKind CreateUserRequest_UserKind
	// Parse user kind from string to custom type
	// Encryptonize expects user type to be of type CreateUserRequest_UserKind
	switch userKindString {
	case "user":
		userKind = CreateUserRequest_USER
	case "admin":
		userKind = CreateUserRequest_ADMIN
	default:
		log.Fatalf("%v\n", utils.Fail("Unrecognized user type, only accepts user/admin"))
	}

	// Create client
	client, err := NewClient(userID, userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("CreateUser failed"), err)
	}

	// Call Encryptonize and create a user
	out, err := client.CreateUser(userKind)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("CreateUser failed"), err)
	}

	// Print create user credentials back to user
	log.Printf("%vCredentials: %v", utils.Pass("Successfully created user!\n"), out)

	return nil
}
