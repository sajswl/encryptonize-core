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

type UserScope struct {
	Read              bool
	Create            bool
	Update            bool
	Index             bool
	ObjectPermissions bool
	UserManagement    bool
}

// CreateUser creates a new client and calls CreateUser through the client
func CreateUser(userAT string, userScope UserScope) error {
	// Encryptonize expects user type to be of type []CreateUserRequest_UserScope
	var scopes = []string{}

	if userScope.Read {
		scopes = append(scopes, "READ")
	}
	if userScope.Create {
		scopes = append(scopes, "CREATE")
	}
	if userScope.Update {
		scopes = append(scopes, "UPDATE")
	}
	if userScope.Index {
		scopes = append(scopes, "INDEX")
	}
	if userScope.ObjectPermissions {
		scopes = append(scopes, "OBJECTPERMISSIONS")
	}
	if userScope.UserManagement {
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
	uid, password, err := client.CreateUser(scopes)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("CreateUser failed"), err)
	}

	// Print create user credentials back to user
	log.Printf("%vUID: \"%s\" Password: \"%s\"", utils.Pass("Successfully created user!\n"), uid, password)

	return nil
}

// LoginUser creates a new client and calls LoginUser
func LoginUser(uid, password string) error {
	client, err := NewClient("")
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("LoginUser failed"), err)
	}

	uat, err := client.LoginUser(uid, password)
	if err != nil {
		log.Fatalf("%v: %v", utils.Fail("LoginUser failed"), err)
	}

	// Print login user credentials back to user
	log.Printf("%vUid: \"%s\" AT: \"%s\"", utils.Pass("Successfully logged in user!\n"), uid, uat)

	return nil
}
