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
package storage

import (
	"context"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/common"
	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

const AssociatedDataStoreSuffix = "_aad"
const CiphertextStoreSuffix = "_data"

// API exposed function, encrypts data and stores it in the object store
// Assumes that user credentials are to be found in context metadata
// Errors if authentication or storing fails
func (strg *Storage) Store(ctx context.Context, request *StoreRequest) (*StoreResponse, error) {
	userID, ok := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while storing object")
		log.Error(ctx, err, "Store: Could not typecast userID to uuid.UUID")
		return nil, err
	}

	objectID, err := uuid.NewV4()
	if err != nil {
		log.Error(ctx, err, "Store: Failed to generate new object ID")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}
	objectIDString := objectID.String()

	// Access Object and OEK generation
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err = status.Errorf(codes.Internal, "error encountered while storing object")
		log.Error(ctx, err, "Store: Could not typecast authstorage to AuthStoreTxInterface ")
		return nil, err
	}

	woek, ciphertext, err := strg.DataCryptor.Encrypt(request.Plaintext, request.AssociatedData)
	if err != nil {
		log.Error(ctx, err, "Store: Failed to encrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	err = strg.Authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err != nil {
		log.Error(ctx, err, "Store: Failed to create new access object")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := strg.ObjectStore.Store(ctx, objectIDString+AssociatedDataStoreSuffix, request.AssociatedData); err != nil {
		log.Error(ctx, err, "Store: Failed to store associated data")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := strg.ObjectStore.Store(ctx, objectIDString+CiphertextStoreSuffix, ciphertext); err != nil {
		log.Error(ctx, err, "Store: Failed to store object")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	// All done, commit auth changes
	if err := authStorageTx.Commit(ctx); err != nil {
		log.Error(ctx, err, "Store: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectIDString)
	log.Info(ctx, "Store: Object stored")

	return &StoreResponse{ObjectId: objectIDString}, nil
}

// API exposed function, retrieves a package from storage solution
// Assumes that user credentials are to be found in context metadata
// Errors if authentication, authorization, or retrieving the object fails
func (strg *Storage) Retrieve(ctx context.Context, request *RetrieveRequest) (*RetrieveResponse, error) {
	objectIDString := request.ObjectId
	accessObject, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(*common.AccessObject)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while retrieving object")
		log.Error(ctx, err, "Retrieve: Could not typecast access object to AccessObject")
		return nil, err
	}

	aad, err := strg.ObjectStore.Retrieve(ctx, objectIDString+AssociatedDataStoreSuffix)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to retrieve associated data")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	ciphertext, err := strg.ObjectStore.Retrieve(ctx, objectIDString+CiphertextStoreSuffix)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to retrieve object")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	plaintext, err := strg.DataCryptor.Decrypt(accessObject.GetWOEK(), ciphertext, aad)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to decrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	log.Info(ctx, "Retrieve: Object retrieved")

	return &RetrieveResponse{
		Plaintext:      plaintext,
		AssociatedData: aad,
	}, nil
}

// API exposed function, deletes a package from a storage solution
// Assumes that user credentials are to be found in context metadata
// Errors if authentication, authorization, or deleting the object fails
func (strg *Storage) Delete(ctx context.Context, request *DeleteRequest) (*DeleteResponse, error) {
	objectIDString := request.ObjectId

	// Parse objectID from request
	objectID, err := uuid.FromString(objectIDString)
	if err != nil {
		log.Errorf(ctx, err, "Delete: Failed to parse object ID %s as UUID", objectIDString)
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	err = strg.Authorizer.DeleteAccessObject(ctx, objectID)
	if err != nil {
		log.Error(ctx, err, "Delete: Failed to delete access object")
		return nil, status.Errorf(codes.Internal, "error encountered while deleting access object")
	}

	err = strg.ObjectStore.Delete(ctx, objectIDString)
	if err != nil {
		log.Error(ctx, err, "Delete: Failed to delete object")
		return nil, status.Errorf(codes.Internal, "error encountered while deleting object")
	}

	return &DeleteResponse{}, nil
}

// API exposed function, replaces the object with the provided object ID with
// new data that is encrypted and placed into the object store
// Assumes that user credentials are to be found in context metadata
// Errors if authentication, authorization, or retrieving the access object fails
func (strg *Storage) Update(ctx context.Context, request *UpdateRequest) (*UpdateResponse, error) {
	objectIDString := request.ObjectId
	accessObject, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(*common.AccessObject)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while updating object")
		log.Error(ctx, err, "Update: Could not typecast access object to AccessObject")
		return nil, err
	}

	ciphertext, err := strg.DataCryptor.EncryptWithKey(request.Plaintext, request.AssociatedData, accessObject.GetWOEK())
	if err != nil {
		log.Error(ctx, err, "Update: Failed to encrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while updating object")
	}

	if err := strg.ObjectStore.Store(ctx, objectIDString+AssociatedDataStoreSuffix, request.AssociatedData); err != nil {
		log.Error(ctx, err, "Update: Failed to store associated data")
		return nil, status.Errorf(codes.Internal, "error encountered while updating object")
	}

	if err := strg.ObjectStore.Store(ctx, objectIDString+CiphertextStoreSuffix, ciphertext); err != nil {
		log.Error(ctx, err, "Update: Failed to store object")
		return nil, status.Errorf(codes.Internal, "error encountered while updating object")
	}

	log.Info(ctx, "Update: Object stored")

	return &UpdateResponse{}, nil
}
