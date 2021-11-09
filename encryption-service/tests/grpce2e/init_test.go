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

package grpce2e

import (
	"testing"

	"log"
	"os"

	"encryption-service/common"
)

var endpoint = "127.0.0.1:9000"
var uid string
var pwd string
var protoUserScopes = []common.UserScope{
	common.UserScope_READ,
	common.UserScope_CREATE,
	common.UserScope_INDEX,
	common.UserScope_OBJECTPERMISSIONS,
	common.UserScope_USERMANAGEMENT,
	common.UserScope_UPDATE,
	common.UserScope_DELETE,
}
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
	v, ok = os.LookupEnv("E2E_TEST_HTTPS")
	if ok && v == "true" {
		https = true
	}
	bootstrapUID, ok := os.LookupEnv("E2E_TEST_UID")
	if !ok {
		log.Fatal("E2E_TEST_UID is not set")
	}
	bootstrapPassword, ok := os.LookupEnv("E2E_TEST_PASS")
	if !ok {
		log.Fatal("E2E_TEST_PASS is not set")
	}

	// Create user for tests
	client, err := NewClient(endpoint, https)
	if err != nil {
		log.Fatalf("Couldn't create client: %v", err)
	}
	defer client.Close()

	// Check if the server is alive
	if err := client.HealthCheck(); err != nil {
		log.Fatalf("Couldn't ping test server: %v", err)
	}

	// Login boostrap user
	_, err = client.LoginUser(bootstrapUID, bootstrapPassword)
	if err != nil {
		log.Fatalf("Couldn't login with test bootstrap user: %v", err)
	}

	// Create a new user with test scopes
	createUserResponse, err := client.CreateUser(protoUserScopes)
	if err != nil {
		log.Fatalf("Couldn't create test user: %v", err)
	}

	uid = createUserResponse.UserId
	pwd = createUserResponse.Password

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
