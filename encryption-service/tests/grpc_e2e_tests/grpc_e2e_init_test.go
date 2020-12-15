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
package grpce2e

import (
	"log"
	"os"
	"testing"

	"encryption-service/app"
)

var endpoint = "127.0.0.1:9000"
var uid string
var uat string
var uidAdmin = "00000000-0000-4000-8000-000000000002"
var adminAT = "bearer ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.OWQcxNqqdofSXdBMaeiXaM4BV1bgusy-umfJGhOQI5g"
var protoUserScopes = []app.CreateUserRequest_UserScope{app.CreateUserRequest_READ, app.CreateUserRequest_CREATE, app.CreateUserRequest_INDEX, app.CreateUserRequest_OBJECTPERMISSIONS}
var protoAdminScopes = []app.CreateUserRequest_UserScope{app.CreateUserRequest_USERMANAGEMENT}
var https = false

/**************************/
/*       Test setup       */
/**************************/

func TestMain(m *testing.M) {
	// Get test enpoint, UID, and UAT
	v, ok := os.LookupEnv("E2E_TEST_URL")
	if ok {
		endpoint = v
	}
	v, ok = os.LookupEnv("E2E_TEST_ADMIN_AT")
	if ok {
		adminAT = v
	}
	v, ok = os.LookupEnv("E2E_TEST_ADMIN_UID")
	if ok {
		uidAdmin = v
	}
	v, ok = os.LookupEnv("E2E_TEST_HTTPS")
	if ok && v == "true" {
		https = true
	}

	// Create user for tests
	client, err := NewClient(endpoint, adminAT, https)
	if err != nil {
		log.Fatalf("Couldn't create client: %v", err)
	}
	defer client.Close()
	createUserResponse, err := client.CreateUser(protoUserScopes)
	if err != nil {
		log.Fatalf("Couldn't create test user: %v", err)
	}
	uat = createUserResponse.AccessToken
	uid = createUserResponse.UserId

	os.Exit(m.Run())
}

/*************************************/
/*    End-to-end helper functions    */
/*************************************/

func closeClient(client *Client, t *testing.T) {
	if err := client.Close(); err != nil {
		t.Fatalf("Failed to close client connection")
	}
}

func failOnError(message string, err error, t *testing.T) {
	if err != nil {
		t.Fatalf(message+": %v", err)
	}
}

func failOnSuccess(message string, err error, t *testing.T) {
	if err == nil {
		t.Fatalf("Test expected to fail: %v", message)
	}
}

func find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
