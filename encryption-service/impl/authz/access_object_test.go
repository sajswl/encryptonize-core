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
package authz

import (
	"reflect"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/impl/crypt"
)

var objectID = uuid.Must(uuid.FromString("F0000000-0000-0000-0000-000000000000"))
var accessObject = &AccessObject{
	Version: 1337,
	UserIDs: map[uuid.UUID]bool{
		uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")): true,
		uuid.Must(uuid.FromString("40000000-0000-0000-0000-000000000000")): true,
	},
	Woek: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
}

func TestContainsUserTrue(t *testing.T) {
	for userID := range accessObject.UserIDs {
		exists := accessObject.ContainsUser(userID)

		if !exists {
			t.Error("UserContains returned false")
		}
	}
}

func TestContainsUserFalse(t *testing.T) {
	exists := accessObject.ContainsUser(uuid.Must(uuid.NewV4()))
	if exists {
		t.Error("UserContains returned true")
	}
}

func TestAdd(t *testing.T) {
	accessObject := &AccessObject{
		UserIDs: map[uuid.UUID]bool{},
	}

	expected := map[uuid.UUID]bool{}
	for i := 0; i < 256; i++ {
		u := uuid.Must(uuid.NewV4())
		accessObject.AddUser(u)

		expected[u] = true

		if !reflect.DeepEqual(expected, accessObject.UserIDs) {
			t.Error("AddUser failed")
		}
	}
}

func TestAddDuplicate(t *testing.T) {
	expected := accessObject.UserIDs
	accessObject.AddUser(uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")))

	if !reflect.DeepEqual(expected, accessObject.UserIDs) {
		t.Error("AddUserDuplicate failed")
	}
}

func TestNew(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	woek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	accessObject := NewAccessObject(userID, woek)
	if err != nil {
		t.Fatalf("NewAccessObject errored: %v", err)
	}

	expected := &AccessObject{
		UserIDs: map[uuid.UUID]bool{
			userID: true,
		},
		Woek:    woek,
		Version: 0,
	}

	if !reflect.DeepEqual(expected, accessObject) {
		t.Error("New failed")
	}
}

//nolint: gosec
func TestRemoveUser(t *testing.T) {
	for userID := range accessObject.UserIDs {
		accessObject.RemoveUser(userID)
		exists := accessObject.ContainsUser(userID)
		if exists {
			t.Error("RemoveUser failed")
		}
	}
}
