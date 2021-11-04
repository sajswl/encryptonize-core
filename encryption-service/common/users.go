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
package common

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
)

// ScopeType represents the different scopes a user could be granted
type ScopeType uint64

const ScopeNone ScopeType = 0
const (
	ScopeRead ScopeType = 1 << iota
	ScopeCreate
	ScopeUpdate
	ScopeDelete
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

const baseAppPath string = "/app.Encryptonize/"
const baseStoragePath string = "/storage.Encryptonize/"
const baseAuthPath string = "/authn.Encryptonize/"
const baseAuthzPath string = "/authz.Encryptonize/"
const baseEncPath string = "/enc.Encryptonize/"

var MethodScopeMap = map[string]ScopeType{
	baseAuthPath + "CreateUser":        ScopeUserManagement,
	baseAuthPath + "RemoveUser":        ScopeUserManagement,
	baseAuthzPath + "GetPermissions":   ScopeIndex,
	baseAuthzPath + "AddPermission":    ScopeObjectPermissions,
	baseAuthzPath + "RemovePermission": ScopeObjectPermissions,
	baseStoragePath + "Store":          ScopeCreate,
	baseStoragePath + "Update":         ScopeUpdate,
	baseStoragePath + "Retrieve":       ScopeRead,
	baseStoragePath + "Delete":         ScopeDelete,
	baseEncPath + "Encrypt":            ScopeCreate,
	baseEncPath + "Decrypt":            ScopeRead,
	baseAppPath + "Version":            ScopeNone,
}

type UserData struct {
	HashedPassword []byte
	Salt           []byte
	GroupIDs       map[uuid.UUID]bool
}

type ProtectedUserData struct {
	UserID     uuid.UUID
	UserData   []byte
	WrappedKey []byte
	DeletedAt  *time.Time
}

func (us ScopeType) IsValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

func (us ScopeType) HasScopes(tar ScopeType) bool {
	return (us & tar) == tar
}

func MapScopesToScopeType(scopes []UserScope) (ScopeType, error) {
	var userScopes ScopeType
	for _, scope := range scopes {
		switch scope {
		case UserScope_READ:
			userScopes |= ScopeRead
		case UserScope_CREATE:
			userScopes |= ScopeCreate
		case UserScope_UPDATE:
			userScopes |= ScopeUpdate
		case UserScope_DELETE:
			userScopes |= ScopeDelete
		case UserScope_INDEX:
			userScopes |= ScopeIndex
		case UserScope_OBJECTPERMISSIONS:
			userScopes |= ScopeObjectPermissions
		case UserScope_USERMANAGEMENT:
			userScopes |= ScopeUserManagement
		default:
			return 0, fmt.Errorf("CreateUser: Invalid scope %v", scopes)
		}
	}
	return userScopes, nil
}

func MapStringToScopeType(scopes string) (ScopeType, error) {
	var userScopes ScopeType
	for _, scope := range scopes {
		switch string(scope) {
		case "r":
			userScopes |= ScopeRead
		case "c":
			userScopes |= ScopeCreate
		case "u":
			userScopes |= ScopeUpdate
		case "d":
			userScopes |= ScopeDelete
		case "i":
			userScopes |= ScopeIndex
		case "o":
			userScopes |= ScopeObjectPermissions
		case "m":
			userScopes |= ScopeUserManagement
		default:
			return 0, fmt.Errorf("CreateUser: Invalid scope %v", string(scope))
		}
	}
	return userScopes, nil
}
