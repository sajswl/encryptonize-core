package enc

import (
	"context"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
	"encryption-service/services/authz"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// API exposed function, encrypts provided plaintext with
func (enc *Enc) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	userID, ok := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while storing object")
		log.Error(ctx, err, "Encrypt: Could not typecast userID to uuid.UUID")
		return nil, err
	}

	objectID, err := uuid.NewV4()
	if err != nil {
		log.Error(ctx, err, "Encrypt: Failed to generate new object ID")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}
	objectIDString := objectID.String()

	// Access Object and OEK generation
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err = status.Errorf(codes.Internal, "error encountered while storing object")
		log.Error(ctx, err, "Encrypt: Could not typecast authstorage to AuthStoreTxInterface ")
		return nil, err
	}

	woek, ciphertext, err := enc.DataCryptor.Encrypt(request.Object.Plaintext, request.Object.AssociatedData)
	if err != nil {
		log.Error(ctx, err, "Encrypt: Failed to encrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while encrypting object")
	}

	err = enc.Authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err != nil {
		log.Error(ctx, err, "Encrypt: Failed to create new access object")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	if err := authStorageTx.Commit(ctx); err != nil {
		log.Error(ctx, err, "Encrypt: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectIDString)
	log.Info(ctx, "Encrypt: Object stored")

	return &EncryptResponse{
		Ciphertext: ciphertext,
	}, nil
}

func (enc *Enc) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	objectIDString := request.ObjectId
	accessObject, err := authz.AuthorizeWrapper(ctx, enc.Authorizer, objectIDString)
	if err != nil {
		// AuthorizeWrapper logs and generates user facing error, just pass it on here
		return nil, err
	}

	plaintext, err := enc.DataCryptor.Decrypt(request.Woek, request.Ciphertext, request.AssociatedData)
	if err != nil {
		log.Error(ctx, err, "Retrieve: Failed to decrypt object")
		return nil, status.Errorf(codes.Internal, "error encountered while retrieving object")
	}

	return &DecryptResponse{
		Plaintext: plaintext,
	}, nil
}
