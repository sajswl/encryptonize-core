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
package enc

import (
	"context"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

const AssociatedDataStoreSuffix = "_aad"
const CiphertextStoreSuffix = "_data"

// API exposed function, encrypts data and stores it in the object store
// Assumes that user credentials are to be found in context metadata
// Errors if authentication or storing fails
func (enc *Enc) Store(ctx context.Context, request *StoreRequest) (*StoreResponse, error) {
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

	woek, ciphertext, err := enc.DataCryptor.Encrypt(request.Object.Plaintext, request.Object.AssociatedData)
	if err != nil {
		log.Error(ctx, err, "Store: Failed to encrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	err = enc.Authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err != nil {
		log.Error(ctx, err, "Store: Failed to create new access object")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := enc.ObjectStore.Store(ctx, objectIDString+AssociatedDataStoreSuffix, request.Object.AssociatedData); err != nil {
		log.Error(ctx, err, "Store: Failed to store associated data")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := enc.ObjectStore.Store(ctx, objectIDString+CiphertextStoreSuffix, ciphertext); err != nil {
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
func (enc *Enc) Retrieve(ctx context.Context, request *RetrieveRequest) (*RetrieveResponse, error) {
	objectIDString := request.ObjectId
	accessObject, err := AuthorizeWrapper(ctx, enc.Authorizer, objectIDString)
	if err != nil {
		// AuthorizeWrapper logs and generates user facing error, just pass it on here
		return nil, err
	}

	aad, err := enc.ObjectStore.Retrieve(ctx, objectIDString+AssociatedDataStoreSuffix)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to retrieve associated data")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	ciphertext, err := enc.ObjectStore.Retrieve(ctx, objectIDString+CiphertextStoreSuffix)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to retrieve object")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	plaintext, err := enc.DataCryptor.Decrypt(accessObject.GetWOEK(), ciphertext, aad)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to decrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectIDString)
	log.Info(ctx, "Retrieve: Object retrieved")

	return &RetrieveResponse{
		Object: &Object{
			Plaintext:      plaintext,
			AssociatedData: aad,
		},
	}, nil
}
