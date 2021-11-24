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

/////////////////////////////////////////////////////////////////////////
//                               Utility                               //
/////////////////////////////////////////////////////////////////////////

type VersionResponse struct {
	Commit string `json:"commit"`
	Tag    string `json:"tag"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

/////////////////////////////////////////////////////////////////////////
//                           User Management                           //
/////////////////////////////////////////////////////////////////////////

type Scope int

const (
	ScopeRead Scope = iota
	ScopeCreate
	ScopeUpdate
	ScopeDelete
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
)

type CreateUserResponse struct {
	UserID   string `json:"userId"`
	Password string `json:"password"`
}

type CreateGroupResponse struct {
	GroupID string `json:"groupId"`
}

/////////////////////////////////////////////////////////////////////////
//                              Encryption                             //
/////////////////////////////////////////////////////////////////////////

type EncryptResponse struct {
	Ciphertext     []byte `json:"ciphertext"`
	AssociatedData []byte `json:"associatedData"`
	ObjectID       string `json:"objectId"`
}

type DecryptResponse struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associatedData"`
}

/////////////////////////////////////////////////////////////////////////
//                               Storage                               //
/////////////////////////////////////////////////////////////////////////

type StoreResponse struct {
	ObjectID string `json:"objectId"`
}

type RetrieveResponse struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associatedData"`
}

/////////////////////////////////////////////////////////////////////////
//                             Permissions                             //
/////////////////////////////////////////////////////////////////////////

type GetPermissionsResponse struct {
	GroupIDs []string `json:"groupIds"`
}

/////////////////////////////////////////////////////////////////////////
//                               Internal                              //
/////////////////////////////////////////////////////////////////////////

type request struct {
	Scopes         []string `json:"scopes,omitempty"`
	UserID         string   `json:"user_id,omitempty"`
	GroupID        string   `json:"group_id,omitempty"`
	Target         string   `json:"target,omitempty"`
	ObjectID       string   `json:"object_id,omitempty"`
	Plaintext      []byte   `json:"plaintext,omitempty"`
	Ciphertext     []byte   `json:"ciphertext,omitempty"`
	AssociatedData []byte   `json:"associated_data,omitempty"`
	Password       string   `json:"password,omitempty"`
}

type accessToken struct {
	Token string `json:"accessToken"`
}
