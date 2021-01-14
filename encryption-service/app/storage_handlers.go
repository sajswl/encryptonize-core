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
package app

import (
	"context"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authstorage"
	"encryption-service/authz"
	"encryption-service/contextkeys"
	"encryption-service/crypt"
	log "encryption-service/logger"
)

const AssociatedDataStoreSuffix = "_aad"
const CiphertextStoreSuffix = "_data"

// API exposed function, encrypts data and stores it in the object store
// Assumes that user credentials are to be found in context metadata
// Errors if authentication or storing fails
func (app *App) Store(ctx context.Context, request *StoreRequest) (*StoreResponse, error) {
	userID, ok := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while storing object")
		log.Error(ctx, "Store: Could not parse userID from context", err)

		return nil, err
	}

	objectID, err := uuid.NewV4()
	if err != nil {
		log.Error(ctx, "Store: Failed to generate new object ID", err)
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}
	objectIDString := objectID.String()

	// Access Object and OEK generation
	authStorage, ok := ctx.Value(contextkeys.AuthStorageCtxKey).(authstorage.AuthStoreInterface)
	if !ok {
		err = status.Errorf(codes.Internal, "error encountered while storing object")
		log.Error(ctx, "Store: Could not parse authStorage from context", err)

		return nil, err
	}

	authorizer := &authz.Authorizer{
		MessageAuthenticator: app.MessageAuthenticator,
		Store:                authStorage,
	}

	oek, err := authorizer.CreateObject(ctx, objectID, userID, app.Config.KEK)
	if err != nil {
		log.Error(ctx, "Store: Failed to create new access object", err)
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	// TODO: Refactor this abstraction
	crypter := &crypt.Crypter{}
	ciphertext, err := crypter.Encrypt(request.Object.Plaintext, request.Object.AssociatedData, oek)
	if err != nil {
		log.Error(ctx, "Store: Failed to encrypt object", err)
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := app.ObjectStore.Store(ctx, objectIDString+AssociatedDataStoreSuffix, request.Object.AssociatedData); err != nil {
		log.Error(ctx, "Store: Failed to store associated data", err)
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := app.ObjectStore.Store(ctx, objectIDString+CiphertextStoreSuffix, ciphertext); err != nil {
		log.Error(ctx, "Store: Failed to store object", err)
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	// All done, commit auth changes
	if err := authStorage.Commit(ctx); err != nil {
		log.Error(ctx, "Store: Failed to commit auth storage transaction", err)
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectIDString)
	log.Info(ctx, "Store: Object stored")

	return &StoreResponse{ObjectId: objectIDString}, nil
}

// API exposed function, retrieves a package from storage solution
// Assumes that user credentials are to be found in context metadata
// Errors if authentication, authorization, or retrieving the object fails
func (app *App) Retrieve(ctx context.Context, request *RetrieveRequest) (*RetrieveResponse, error) {
	objectIDString := request.ObjectId
	_, accessObject, err := AuthorizeWrapper(ctx, app.MessageAuthenticator, objectIDString)
	if err != nil {
		// AuthorizeWrapper logs and generates user facing error, just pass it on here
		return nil, err
	}

	oek, err := accessObject.UnwrapWOEK(app.Config.KEK)
	if err != nil {
		log.Error(ctx, "Retrieve: Failed to unwrap OEK", err)
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	aad, err := app.ObjectStore.Retrieve(ctx, objectIDString+AssociatedDataStoreSuffix)
	if err != nil {
		log.Error(ctx, "Retrieve: Failed to retrieve associated data", err)
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	ciphertext, err := app.ObjectStore.Retrieve(ctx, objectIDString+CiphertextStoreSuffix)
	if err != nil {
		log.Error(ctx, "Retrieve: Failed to retrieve object", err)
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	// TODO: Refactor this abstraction
	crypter := &crypt.Crypter{}
	plaintext, err := crypter.Decrypt(ciphertext, aad, oek)
	if err != nil {
		log.Error(ctx, "Retrieve: Failed to decrypt object", err)
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
