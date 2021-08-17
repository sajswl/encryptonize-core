package enc

import (
	"bytes"
	context "context"
	"encryption-service/contextkeys"
	"encryption-service/impl/authstorage"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
	"testing"

	"github.com/gofrs/uuid"
)

var ma, _ = crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), crypt.AccessObjectsDomain)
var authorizer = &authzimpl.Authorizer{
	AccessObjectMAC: ma,
}

func TestEncryptDecrypt(t *testing.T) {
	authStore := authstorage.NewMemoryAuthStore()
	authStorageTx, _ := authStore.NewTransaction(context.TODO())
	cryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	enc := Enc{
		Authorizer:  authorizer,
		DataCryptor: cryptor,
	}

	object := &Object{
		Plaintext:      []byte("plaintext_bytes"),
		AssociatedData: []byte("associated_data_bytes"),
	}

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStorageTx)
	encryptResponse, err := enc.Encrypt(
		ctx,
		&EncryptRequest{
			Object: object,
		},
	)

	if err != nil {
		t.Fatalf("Encrypting object failed: %v", err)
	}

	decryptResponse, err := enc.Decrypt(
		ctx,
		&DecryptRequest{
			ObjectId:       encryptResponse.ObjectId,
			Ciphertext:     encryptResponse.Ciphertext,
			AssociatedData: object.AssociatedData,
		},
	)

	if err != nil {
		t.Fatalf("Decrypting object failed: %v", err)
	}

	comp := bytes.Compare(decryptResponse.Plaintext, object.Plaintext)
	if comp != 0 {
		t.Fatalf("Decrypted plaintext does not equal original plaintext!")
	}
}

func TestDecryptFail(t *testing.T) {
	cryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	enc := Enc{
		DataCryptor: cryptor,
	}

	fakeRequest := &DecryptRequest{
		Ciphertext:     []byte("fakecipher"),
		AssociatedData: []byte("fakeaad"),
	}

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)

	_, err = enc.Decrypt(ctx, fakeRequest)
	if err == nil {
		t.Fatalf("Decrypt should have errored")
	}
}
