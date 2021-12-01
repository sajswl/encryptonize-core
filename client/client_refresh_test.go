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

package client

import (
	"testing"

	"context"
)

func TestUtilityWR(t *testing.T) {
	c, err := NewClientWR(context.Background(), endpoint, certPath, uid, password)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Health(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Version(); err != nil {
		t.Fatal(err)
	}
}

func TestUserManagementWR(t *testing.T) {
	c, err := NewClientWR(context.Background(), endpoint, certPath, uid, password)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}

	createGroupResponse, err := c.CreateGroup(scopes)
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddUserToGroup(createUserResponse.UserID, createGroupResponse.GroupID)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemoveUserFromGroup(createUserResponse.UserID, createGroupResponse.GroupID)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemoveUser(createUserResponse.UserID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptWR(t *testing.T) {
	c, err := NewClientWR(context.Background(), endpoint, certPath, uid, password)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := c.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	decryptResponse, err := c.Decrypt(encryptResponse.ObjectID, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	if err != nil {
		t.Fatal(err)
	}
	if string(decryptResponse.Plaintext) != string(plaintext) {
		t.Fatal("Decryption returned wrong plaintext")
	}
	if string(decryptResponse.AssociatedData) != string(associatedData) {
		t.Fatal("Decryption returned wrong data")
	}
}

func TestStoreWR(t *testing.T) {
	c, err := NewClientWR(context.Background(), endpoint, certPath, uid, password)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := c.Store(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	retrieveResponse, err := c.Retrieve(storeResponse.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if string(retrieveResponse.Plaintext) != string(plaintext) {
		t.Fatal("Decryption returned wrong plaintext")
	}
	if string(retrieveResponse.AssociatedData) != string(associatedData) {
		t.Fatal("Decryption returned wrong data")
	}

	plaintext = []byte("foobar")
	associatedData = []byte("barbaz")
	err = c.Update(storeResponse.ObjectID, plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	err = c.Delete(storeResponse.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPermissionsWR(t *testing.T) {
	c, err := NewClientWR(context.Background(), endpoint, certPath, uid, password)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := c.Store(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddPermission(storeResponse.ObjectID, createUserResponse.UserID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.GetPermissions(storeResponse.ObjectID)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemovePermission(storeResponse.ObjectID, createUserResponse.UserID)
	if err != nil {
		t.Fatal(err)
	}
}
