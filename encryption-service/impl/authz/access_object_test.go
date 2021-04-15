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
	"bytes"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/impl/crypt"
)

var objectID = uuid.Must(uuid.FromString("F0000000-0000-0000-0000-000000000000"))
var accessObject = &AccessObject{
	Version: 1337,
	UserIds: [][]byte{
		uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")).Bytes(),
		uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000")).Bytes(),
		uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")).Bytes(),
		uuid.Must(uuid.FromString("40000000-0000-0000-0000-000000000000")).Bytes(),
	},
	Woek: []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
}

func TestFindUser(t *testing.T) {
	for i, userID := range accessObject.UserIds {
		j, exists := accessObject.findUser(uuid.Must(uuid.FromBytes(userID)))

		if j != i || !exists {
			t.Error("user not found")
		}
	}

	j, exists := accessObject.findUser(uuid.Must(uuid.FromString("00000000-0000-0000-0000-000000000000")))
	if j != 0 || exists {
		t.Error("user 00 wrong")
	}

	j, exists = accessObject.findUser(uuid.Must(uuid.FromString("31000000-0000-0000-0000-000000000000")))
	if j != 3 || exists {
		t.Error("user 31 wrong")
	}

	j, exists = accessObject.findUser(uuid.Must(uuid.FromString("50000000-0000-0000-0000-000000000000")))
	if j != 4 || exists {
		t.Error("user 50 wrong")
	}
}

func TestContainsUserTrue(t *testing.T) {
	for _, userID := range accessObject.UserIds {
		exists := accessObject.ContainsUser(uuid.Must(uuid.FromBytes(userID)))

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
	accessObject := &AccessObject{}

	expected := make([][]byte, 0)
	for i := 0; i < 256; i++ {
		u := uuid.Must(uuid.NewV4())

		accessObject.AddUser(u)

		expected = append(expected, u.Bytes())
		sort.Slice(expected, func(i, j int) bool {
			return bytes.Compare(expected[i], expected[j]) < 0
		})

		if !reflect.DeepEqual(expected, accessObject.UserIds) {
			t.Error("AddUser failed")
		}
	}
}

func TestAddDuplicate(t *testing.T) {
	expected := append([][]byte(nil), accessObject.UserIds...)
	accessObject.AddUser(uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000")))

	if !reflect.DeepEqual(expected, accessObject.UserIds) {
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
		UserIds: [][]byte{
			userID.Bytes(),
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
	accessObject := &AccessObject{}

	expected := make([][]byte, 256)
	for i := 0; i < len(expected); i++ {
		expected[i] = uuid.Must(uuid.NewV4()).Bytes()
	}
	sort.Slice(expected, func(i, j int) bool {
		return bytes.Compare(expected[i], expected[j]) < 0
	})

	accessObject.UserIds = expected

	for i := 0; i < len(expected); i++ {
		j := rand.Intn(len(expected))
		u := uuid.Must(uuid.FromBytes(expected[j]))

		accessObject.RemoveUser(u)

		expected = append(expected[:j], expected[j+1:]...)

		if !reflect.DeepEqual(expected, accessObject.UserIds) {
			t.Error("RemoveUser failed")
		}
	}
}
