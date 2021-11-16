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
)

// ScopeType represents the different scopes a user/group could be granted
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
	baseAuthPath + "CreateUser":          ScopeUserManagement,
	baseAuthPath + "RemoveUser":          ScopeUserManagement,
	baseAuthPath + "CreateGroup":         ScopeUserManagement,
	baseAuthPath + "AddUserToGroup":      ScopeUserManagement,
	baseAuthPath + "RemoveUserFromGroup": ScopeUserManagement,
	baseAuthzPath + "GetPermissions":     ScopeIndex,
	baseAuthzPath + "AddPermission":      ScopeObjectPermissions,
	baseAuthzPath + "RemovePermission":   ScopeObjectPermissions,
	baseStoragePath + "Store":            ScopeCreate,
	baseStoragePath + "Update":           ScopeUpdate,
	baseStoragePath + "Retrieve":         ScopeRead,
	baseStoragePath + "Delete":           ScopeDelete,
	baseEncPath + "Encrypt":              ScopeCreate,
	baseEncPath + "Decrypt":              ScopeRead,
	baseAppPath + "Version":              ScopeNone,
}

// IsValid checks if the given scope is one of the defined scopes
func (us ScopeType) IsValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

// HasScopes returns true of `target` is in the set of scopes
func (us ScopeType) HasScopes(target ScopeType) bool {
	return (us & target) == target
}

// MapScopesToScopeType converts between the protobuf scope the in the internal scope type
func MapScopesToScopeType(protoScopes []Scope) (ScopeType, error) {
	var scopes ScopeType
	for _, scope := range protoScopes {
		switch scope {
		case Scope_READ:
			scopes |= ScopeRead
		case Scope_CREATE:
			scopes |= ScopeCreate
		case Scope_UPDATE:
			scopes |= ScopeUpdate
		case Scope_DELETE:
			scopes |= ScopeDelete
		case Scope_INDEX:
			scopes |= ScopeIndex
		case Scope_OBJECTPERMISSIONS:
			scopes |= ScopeObjectPermissions
		case Scope_USERMANAGEMENT:
			scopes |= ScopeUserManagement
		default:
			return 0, fmt.Errorf("Invalid scope %v", scopes)
		}
	}
	return scopes, nil
}

// MapStringToScopeType converts a string of scope shorthands to a set of scopes
func MapStringToScopes(scopesString string) ([]Scope, error) {
	scopes := make([]Scope, 0, len(scopesString))
	for _, scope := range scopesString {
		switch string(scope) {
		case "r":
			scopes = append(scopes, Scope_READ)
		case "c":
			scopes = append(scopes, Scope_CREATE)
		case "u":
			scopes = append(scopes, Scope_UPDATE)
		case "d":
			scopes = append(scopes, Scope_DELETE)
		case "i":
			scopes = append(scopes, Scope_INDEX)
		case "o":
			scopes = append(scopes, Scope_OBJECTPERMISSIONS)
		case "m":
			scopes = append(scopes, Scope_USERMANAGEMENT)
		default:
			return nil, fmt.Errorf("Invalid scope %v", string(scope))
		}
	}
	return scopes, nil
}
