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
package authz

import (
	"bytes"
	"sort"

	"github.com/gofrs/uuid"

	"encryption-service/crypt"
)

// Extensions for the generated AccessObject:
// UsersIds are inserted in a sorted order (insertion sort) to allow for binary search

// NewAccessObject instantiates a new Access Object with given userID and KEK. The Access Object is
// returned along with the generated OEK. A new object starts with Version: 0
func NewAccessObject(userID uuid.UUID, kek []byte) (*AccessObject, []byte, error) {
	oek, err := crypt.Random(32)
	if err != nil {
		return nil, nil, err
	}

	keywrap, err := crypt.NewKWP(kek)
	if err != nil {
		return nil, nil, err
	}

	woek, err := keywrap.Wrap(oek)
	if err != nil {
		return nil, nil, err
	}

	accessObject := &AccessObject{
		UserIds: [][]byte{userID.Bytes()},
		Woek:    woek,
	}

	return accessObject, oek, nil
}

// UnwrapWOEK unwraps the WOEK of the Access Object to extract the OEK
func (a *AccessObject) UnwrapWOEK(kek []byte) ([]byte, error) {
	keywrap, err := crypt.NewKWP(kek)
	if err != nil {
		return nil, err
	}

	oek, err := keywrap.Unwrap(a.Woek)
	if err != nil {
		return nil, err
	}

	return oek, nil
}

// AddUser adds a new userID to an Access Object
// TODO: return error on existing user?
func (a *AccessObject) AddUser(userID uuid.UUID) {
	i, exists := a.findUser(userID)
	if exists {
		return
	}

	a.UserIds = append(a.UserIds, nil)
	copy(a.UserIds[i+1:], a.UserIds[i:])
	a.UserIds[i] = userID.Bytes()
}

// ContainsUser returns whether a userID is in the AccessObject
func (a *AccessObject) ContainsUser(userID uuid.UUID) bool {
	_, exists := a.findUser(userID)
	return exists
}

// AddUser removes a userID from an Access Object
// TODO: return error on non-existing user?
func (a *AccessObject) RemoveUser(userID uuid.UUID) {
	i, exists := a.findUser(userID)
	if exists {
		a.UserIds = append(a.UserIds[:i], a.UserIds[i+1:]...)
	}
}

// findUser returns:
// - the index of the first usersID that is >= than the given userID (can be after the last element)
// - if the given userID is contained within the userIDs
func (a *AccessObject) findUser(userID uuid.UUID) (int, bool) {
	u := userID.Bytes()
	i := sort.Search(len(a.UserIds), func(i int) bool {
		return bytes.Compare(a.UserIds[i], u) >= 0
	})
	return i, i < len(a.UserIds) && bytes.Equal(a.UserIds[i], u)
}

// Converts an array of byte arrays to a list of strings
func (a *AccessObject) MakeUIDStringList() ([]string, error) {
	uidsBytes := a.UserIds
	uids := make([]string, len(uidsBytes))
	for i, uid := range uidsBytes {
		newUID, err := uuid.FromBytes(uid)
		if err != nil {
			return nil, err
		}

		uids[i] = newUID.String()
	}
	return uids, nil
}
