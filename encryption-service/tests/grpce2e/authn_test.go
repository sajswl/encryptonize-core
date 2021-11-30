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
)

type LoginDetails struct {
	userid, password string
}

func TestAuthenticated(t *testing.T) {
	client, err := NewClient(endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	newUser, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	_, err = client.LoginUser(newUser.UserId, newUser.Password)
	failOnError("Could not log in user", err, t)
}

func TestWrongCredentials(t *testing.T) {
	client, err := NewClient(endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	newUser, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	wrongCredentials := []LoginDetails{
		LoginDetails{userid: "", password: ""},
		LoginDetails{userid: "", password: pwd},
		LoginDetails{userid: uid, password: ""},
		LoginDetails{userid: uid, password: "wrong password"},
		LoginDetails{userid: newUser.UserId, password: pwd},
		LoginDetails{userid: newUser.UserId, password: "wrong password"},
	}

	for _, cred := range wrongCredentials {
		_, err = client.LoginUser(cred.userid, cred.password)
		failOnSuccess("Should not be able to log in with wrong credentials", err, t)
	}
}

func TestWrongToken(t *testing.T) {
	client, err := NewClient(endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	badTokens := []string{
		"bad__bad__token!",
		"ChAAAAAAAAXXXXAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-nXpZ7tSWsAYgaDHjAEc1sUA",
		"ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-nXpZ7tSWsAYgaDHjAEc1sUA",
		"ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAA+-~/AAAAAAAAg.47THgf10Vei2v55TGZP-nXpZ7tSWsAYgaDHjAEc1sUA",
		"ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-+-~/7tSWsAYgaDHjAEc1sUA",
		"extra.ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-+-~/7tSWsAYgaDHjAEc1sUA",
		"ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAA.47THgf10Vei2v55TGZP-nXpZ7tSWsAYgaDHjAEc1sUA",
		"ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-",
		"BAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-nXpZ7tSWsAYgaDHjAEc1sUA",
		"",
	}

	for _, token := range badTokens {
		client.SetToken(token)

		_, err = client.GetVersion()
		failOnSuccess("Should not be able to get version with a wrong token", err, t)
	}
}
