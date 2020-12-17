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
	"context"
	"errors"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"

	"encryption-service/authstorage"
	"encryption-service/crypt"
)

// Authorizer encapsulates a MessageAuthenticator and a backing Auth Storage for reading and writing Access Objects
type Authorizer struct {
	MessageAuthenticator *crypt.MessageAuthenticator
	Store                authstorage.AuthStoreInterface
}

// serializeAccessObject serializes and signs an Object ID + Access Object into data + tag
func (a *Authorizer) SerializeAccessObject(objectID uuid.UUID, accessObject *AccessObject) ([]byte, []byte, error) {
	data, err := proto.Marshal(accessObject)
	if err != nil {
		return nil, nil, err
	}

	msg := append(objectID.Bytes(), data...) // TODO: move linking to MessageAuthenticator?
	tag, err := a.MessageAuthenticator.Tag(crypt.AccessObjectsDomain, msg)
	if err != nil {
		return nil, nil, err
	}

	return data, tag, nil
}

// parseAccessObject verifies and parses an Object ID + data + tag into an Access Object
func (a *Authorizer) ParseAccessObject(objectID uuid.UUID, data, tag []byte) (*AccessObject, error) {
	msg := append(objectID.Bytes(), data...) // TODO: move linking to MessageAuthenticator?
	valid, err := a.MessageAuthenticator.Verify(crypt.AccessObjectsDomain, msg, tag)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid tag")
	}

	accessObject := &AccessObject{}
	err = proto.Unmarshal(data, accessObject)
	if err != nil {
		return nil, err
	}

	return accessObject, nil
}

// Use cases for authorizer:

// CreateObject creates a new object with given parameters and inserts it into the Auth Store,
// returning the associated OEK.
func (a *Authorizer) CreateObject(ctx context.Context, objectID, userID uuid.UUID, kek []byte) ([]byte, error) {
	accessObject, oek, err := NewAccessObject(userID, kek)
	if err != nil {
		return nil, err
	}

	data, tag, err := a.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		return nil, err
	}

	err = a.Store.InsertAcccessObject(ctx, objectID, data, tag)
	if err != nil {
		return nil, err
	}

	return oek, nil
}

// Authorize checks if a userID is allowed to access the objectID
func (a *Authorizer) Authorize(ctx context.Context, objectID, userID uuid.UUID) (*AccessObject, bool, error) {
	// TODO: add single row special case?
	data, tag, err := a.Store.GetAccessObject(ctx, objectID)
	if err != nil {
		return nil, false, err
	}

	accessObject, err := a.ParseAccessObject(objectID, data, tag)
	if err != nil {
		return nil, false, err
	}

	ok := accessObject.ContainsUser(userID)
	if !ok {
		return nil, false, nil
	}

	return accessObject, true, nil
}

// AddPermission adds a userID to the allowed users of the objectID and updates the Auth Storage
func (a *Authorizer) AddPermission(ctx context.Context, accessObject *AccessObject, objectID, targetUserID uuid.UUID) error {
	accessObject.AddUser(targetUserID)

	return a.updatePermissions(ctx, objectID, accessObject)
}

// RemovePermission removes an userID to the allowed users of the objectID and updates the Auth Storage
func (a *Authorizer) RemovePermission(ctx context.Context, accessObject *AccessObject, objectID, targetUserID uuid.UUID) error {
	// TODO: check non exists?
	accessObject.RemoveUser(targetUserID)

	return a.updatePermissions(ctx, objectID, accessObject)
}

// updatePermissions increments the Access Object's version and updates in the Auth Storage
func (a *Authorizer) updatePermissions(ctx context.Context, objectID uuid.UUID, accessObject *AccessObject) error {
	accessObject.Version++

	data, tag, err := a.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		return err
	}

	err = a.Store.UpdateAccessObject(ctx, objectID, data, tag)
	if err != nil {
		return err
	}

	return nil
}
