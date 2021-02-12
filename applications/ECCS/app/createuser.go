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

// CreateUser creates a new client and calls CreateUser through the client
func CreateUser(userAT string, read, create, index, objectPermissions, userManagement bool) error {
	// Encryptonize expects user type to be of type []CreateUserRequest_UserScope
	var scopes = []string{}

	if read {
		scopes = append(scopes, "READ")
	}
	if create {
		scopes = append(scopes, "CREATE")
	}
	if index {
		scopes = append(scopes, "INDEX")
	}
	if objectPermissions {
		scopes = append(scopes, "OBJECTPERMISSIONS")
	}
	if userManagement {
		scopes = append(scopes, "USERMANAGEMENT")
	}

	if len(scopes) < 1 {
		log.Fatalf("%v: At least a single scope is required", utils.Fail("CreateUser failed"))
	}

	// Create client
	client, err := NewClient(userAT)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("CreateUser failed"), err)
	}

	// Call Encryptonize and create a user
	uid, at, err := client.CreateUser(scopes)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("CreateUser failed"), err)
	}

	// Print create user credentials back to user
	log.Printf("%vUID: \"%s\" AT: \"%s\"", utils.Pass("Successfully created user!\n"), uid, at)

	return nil
}
