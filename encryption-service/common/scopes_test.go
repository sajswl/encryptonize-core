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
	"testing"
)

func TestIsValid(t *testing.T) {
	validScopes := []ScopeType{
		ScopeCreate,
		ScopeUpdate,
		ScopeDelete,
		ScopeIndex,
		ScopeObjectPermissions,
		ScopeUserManagement,
	}

	for _, scope := range validScopes {
		if err := scope.IsValid(); err != nil {
			t.Error("Scope should have been valid")
		}
	}
}

func TestIsNotValid(t *testing.T) {
	scopeInvalid := ScopeEnd
	if err := scopeInvalid.IsValid(); err == nil {
		t.Error("IsValid should have failed for a scope out of range")
	}
}

func TestMapScopes(t *testing.T) {
	scopesString := "rcudiom"

	protoScopes, err := MapStringToScopes(scopesString)
	if err != nil {
		t.Error("Failed to map string to scopes")
	}
	scopes, err := MapScopesToScopeType(protoScopes)
	if err != nil {
		t.Error("Failed to map scopes to scope type")
	}
	if !scopes.HasScopes(ScopeRead) {
		t.Error("Expected HasScopes to have ScopeRead")
	}
	if !scopes.HasScopes(ScopeCreate) {
		t.Error("Expected HasScopes to have ScopeCreate")
	}
	if !scopes.HasScopes(ScopeUpdate) {
		t.Error("Expected HasScopes to have ScopeUpdate")
	}
	if !scopes.HasScopes(ScopeDelete) {
		t.Error("Expected HasScopes to have ScopeDelete")
	}
	if !scopes.HasScopes(ScopeIndex) {
		t.Error("Expected HasScopes to have ScopeIndex")
	}
	if !scopes.HasScopes(ScopeObjectPermissions) {
		t.Error("Expected HasScopes to have ScopeObjectPermissions")
	}
	if !scopes.HasScopes(ScopeUserManagement) {
		t.Error("Expected HasScopes to have ScopeUserManagement")
	}
}

func TestMapMissingScope(t *testing.T) {
	scopesString := "r"

	protoScopes, err := MapStringToScopes(scopesString)
	if err != nil {
		t.Error("Failed to map string to scopes")
	}
	scopes, err := MapScopesToScopeType(protoScopes)
	if err != nil {
		t.Error("Failed to map scopes to scope type")
	}
	if !scopes.HasScopes(ScopeRead) {
		t.Error("Expected HasScopes to have ScopeRead")
	}
	if scopes.HasScopes(ScopeCreate) {
		t.Error("HasScopes should not have ScopeCreate")
	}
}

func TestMapStringInvalidScope(t *testing.T) {
	invalidScope := "x"

	_, err := MapStringToScopes(invalidScope)
	if err == nil {
		t.Error("MapStringToScopes should have failed because of invalid scope")
	}
}
