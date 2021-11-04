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
	"context"
	"errors"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/interfaces"
)

// Authorizer encapsulates a MessageAuthenticator and a backing Auth Storage for reading and writing Access Objects
type Authorizer struct {
	AccessObjectCryptor interfaces.CryptorInterface
}

// CreateObject creates a new object with given parameters and inserts it into the Auth Store.
func (a *Authorizer) CreateAccessObject(ctx context.Context, objectID, userID uuid.UUID, woek []byte) error {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	accessObject := common.NewAccessObject(userID, woek)
	wrappedKey, ciphertext, err := a.AccessObjectCryptor.EncodeAndEncrypt(accessObject, objectID.Bytes())
	if err != nil {
		return err
	}

	protected := common.ProtectedAccessObject{
		ObjectID:     objectID,
		AccessObject: ciphertext,
		WrappedKey:   wrappedKey,
	}

	err = authStorageTx.InsertAcccessObject(ctx, protected)
	if err != nil {
		return err
	}

	return nil
}

// FetchAccessObject fetches an AccessObject by its ID and decrypts it
func (a *Authorizer) FetchAccessObject(ctx context.Context, objectID uuid.UUID) (*common.AccessObject, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	protected, err := authStorageTx.GetAccessObject(ctx, objectID)
	if err != nil {
		return nil, err
	}

	accessObject := &common.AccessObject{}
	err = a.AccessObjectCryptor.DecodeAndDecrypt(accessObject, protected.WrappedKey, protected.AccessObject, objectID.Bytes())
	if err != nil {
		return nil, err
	}

	return accessObject, nil
}

// updatePermissions increments the Access Object's version and updates in the Auth Storage
func (a *Authorizer) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, accessObject common.AccessObject) error {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	accessObject.Version++

	wrappedKey, ciphertext, err := a.AccessObjectCryptor.EncodeAndEncrypt(accessObject, objectID.Bytes())
	if err != nil {
		return err
	}

	protected := common.ProtectedAccessObject{
		ObjectID:     objectID,
		AccessObject: ciphertext,
		WrappedKey:   wrappedKey,
	}

	err = authStorageTx.UpdateAccessObject(ctx, protected)
	if err != nil {
		return err
	}

	return nil
}

func (a *Authorizer) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) (err error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	err = authStorageTx.DeleteAccessObject(ctx, objectID)
	if err != nil {
		return err
	}

	return authStorageTx.Commit(ctx)
}
