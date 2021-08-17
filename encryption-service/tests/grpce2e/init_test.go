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
	"encryption-service/users"
	"log"
	"os"
	"testing"
)

var endpoint = "127.0.0.1:9000"
var uid string
var uat string
var pwd string
var adminAT = "wgiB4kxBTb3A0lJQNLj1Bm24g1zt-IljDda0fqoS84VfAJ_OoQsbBw.ysFgUjsYhQ_-irx0Yrf3xSeJ-CR-ZnMbq9mbBcHrPKV6g2hdBJnD0jznJJuhnLHlvJd7l20B1w"
var protoUserScopes = []users.UserScope{users.UserScope_READ, users.UserScope_CREATE, users.UserScope_UPDATE, users.UserScope_DELETE,
	users.UserScope_ENCRYPT, users.UserScope_DECRYPT, users.UserScope_INDEX, users.UserScope_OBJECTPERMISSIONS}
var protoAdminScopes = []users.UserScope{users.UserScope_USERMANAGEMENT}
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
	v, ok = os.LookupEnv("E2E_TEST_ADMIN_UAT")
	if ok {
		adminAT = v
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

	// Check if the server is alive
	if err := client.HealthCheck(); err != nil {
		log.Fatalf("Couldn't ping test server: %v", err)
	}

	createUserResponse, err := client.CreateUser(protoUserScopes)
	if err != nil {
		log.Fatalf("Couldn't create test user: %v", err)
	}

	uid = createUserResponse.UserId
	pwd = createUserResponse.Password

	loginUserResponse, err := client.LoginUser(uid, pwd)
	if err != nil {
		log.Fatalf("Couldn't login with test user: %v", err)
	}

	uat = loginUserResponse.AccessToken

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
