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

package app

type Object struct {
	ObjectID string `json:"object_id"`
}

type UpdateObject struct {
	ObjectID       string `json:"object_id"`
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associated_data"`
}

type ObjectPermissions struct {
	ObjectID string `json:"object_id"`
	UserID   string `json:"target"`
}

type Data struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associated_data"`
}

type EncryptedData struct {
	Ciphertext     []byte `json:"ciphertext"`
	AssociatedData []byte `json:"associatedData"`
	ObjectID       string `json:"objectId"`
}

type DecodedEncryptedData struct {
	Ciphertext     string `json:"ciphertext"`
	AssociatedData string `json:"associatedData"`
	ObjectID       string `json:"objectId"`
}

type RetrievedData struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associatedData"`
}

type DecodedRetrievedData struct {
	Plaintext      string `json:"plaintext"`
	AssociatedData string `json:"associated_data"`
}

type User struct {
	UserID string `json:"user_id"`
}

type UserScope struct {
	Read              bool
	Create            bool
	Update            bool
	Delete            bool
	Index             bool
	ObjectPermissions bool
	UserManagement    bool
}

type UserScopes struct {
	Scopes []string `json:"scopes"`
}

type Credentials struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}
