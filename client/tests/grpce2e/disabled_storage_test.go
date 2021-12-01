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

//go:build !storage
// +build !storage

package grpce2e

import (
	"testing"

	"context"

	coreclient "github.com/cyber-crypt-com/encryptonize-core/client"
)

// Test endpoint is disabled
func TestStoreDisabled(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	_, err = client.Store(plaintext, associatedData)
	failOnSuccess("Store operation should have failed", err, t)
}
