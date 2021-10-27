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
	"context"
	"encoding/gob"
	"errors"

	"github.com/gofrs/uuid"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
)

// Authorizer encapsulates a MessageAuthenticator and a backing Auth Storage for reading and writing Access Objects
type Authorizer struct {
	AccessObjectMAC interfaces.MessageAuthenticatorInterface
}

// serializeAccessObject serializes and signs an Object ID + Access Object into data + tag
func (a *Authorizer) SerializeAccessObject(objectID uuid.UUID, accessObject *AccessObject) ([]byte, []byte, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(accessObject)
	if err != nil {
		return nil, nil, err
	}

	data := buffer.Bytes()
	msg := append(objectID.Bytes(), data...)
	tag, err := a.AccessObjectMAC.Tag(msg)
	if err != nil {
		return nil, nil, err
	}

	return data, tag, nil
}

// parseAccessObject verifies and parses an Object ID + data + tag into an Access Object
func (a *Authorizer) ParseAccessObject(objectID uuid.UUID, data, tag []byte) (*AccessObject, error) {
	msg := append(objectID.Bytes(), data...)
	valid, err := a.AccessObjectMAC.Verify(msg, tag)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid tag")
	}

	accessObject := &AccessObject{}
	dec := gob.NewDecoder(bytes.NewReader(data))

	err = dec.Decode(accessObject)
	if err != nil {
		return nil, err
	}

	return accessObject, nil
}

// Use cases for authorizer:

// CreateObject creates a new object with given parameters and inserts it into the Auth Store.
func (a *Authorizer) CreateAccessObject(ctx context.Context, objectID, groupID uuid.UUID, woek []byte) error {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	accessObject := NewAccessObject(groupID, woek)

	data, tag, err := a.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		return err
	}

	err = authStorageTx.InsertAcccessObject(ctx, objectID, data, tag)
	if err != nil {
		return err
	}

	return nil
}

// FetchAccessObject fetches an AccessObject by its ID, deserializes it and verifies its tag
func (a *Authorizer) FetchAccessObject(ctx context.Context, objectID uuid.UUID) (interfaces.AccessObjectInterface, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	// TODO: add single row special case?
	data, tag, err := authStorageTx.GetAccessObject(ctx, objectID)
	if err != nil {
		return nil, err
	}

	// will fail if the tag does not match
	accessObject, err := a.ParseAccessObject(objectID, data, tag)
	if err != nil {
		return nil, err
	}

	return accessObject, nil
}

// updatePermissions increments the Access Object's version and updates in the Auth Storage
func (a *Authorizer) UpsertAccessObject(ctx context.Context, objectID uuid.UUID, accessObject interfaces.AccessObjectInterface) error {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	ao, ok := accessObject.(*AccessObject)
	if !ok {
		return errors.New("accessObject of unexpected dynamic type")
	}

	ao.Version++

	data, tag, err := a.SerializeAccessObject(objectID, ao)
	if err != nil {
		return err
	}

	err = authStorageTx.UpdateAccessObject(ctx, objectID, data, tag)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authorizer) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) (err error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	err = authStorageTx.DeleteAccessObject(ctx, objectID)
	if err != nil {
		return err
	}

	return authStorageTx.Commit(ctx)
}
