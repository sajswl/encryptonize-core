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
	"github.com/gofrs/uuid"
)

type AccessObject struct {
	UserIDs map[uuid.UUID]bool
	Woek    []byte
	Version uint64
}

// NewAccessObject instantiates a new Access Object with given userID and WOEK.
// A new object starts with Version: 0
func NewAccessObject(userID uuid.UUID, woek []byte) *AccessObject {
	return &AccessObject{
		UserIDs: map[uuid.UUID]bool{userID: true},
		Woek:    woek,
	}
}

// AddUser adds a new userID to an Access Object
func (a *AccessObject) AddUser(userID uuid.UUID) {
	a.UserIDs[userID] = true
}

// ContainsUser returns whether a userID is in the AccessObject
func (a *AccessObject) ContainsUser(userID uuid.UUID) bool {
	_, ok := a.UserIDs[userID]
	return ok
}

// RemoveUser removes a userID from an Access Object
func (a *AccessObject) RemoveUser(userID uuid.UUID) {
	delete(a.UserIDs, userID)
}

// GetUsers returns a set of userIDs that may access the Object
func (a *AccessObject) GetUsers() map[uuid.UUID]bool {
	return a.UserIDs
}

// GetWOEK returns the wrapped object encryption key
func (a *AccessObject) GetWOEK() []byte {
	return a.Woek
}
