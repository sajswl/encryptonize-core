package client

import (
	"testing"

	"context"
	"log"
	"os"
)

var uid string
var password string
var certPath = ""
var endpoint = "localhost:9000"

var scopes = []Scope{
	ScopeRead,
	ScopeCreate,
	ScopeUpdate,
	ScopeDelete,
	ScopeIndex,
	ScopeObjectPermissions,
	ScopeUserManagement,
}

func TestMain(m *testing.M) {
	var ok bool
	uid, ok = os.LookupEnv("E2E_TEST_UID")
	if !ok {
		log.Fatal("E2E_TEST_UID must be set")
	}
	password, ok = os.LookupEnv("E2E_TEST_PASS")
	if !ok {
		log.Fatal("E2E_TEST_PASS must be set")
	}
	value, ok := os.LookupEnv("E2E_TEST_CERT")
	if ok {
		certPath = value
	}
	value, ok = os.LookupEnv("E2E_TEST_URL")
	if ok {
		endpoint = value
	}

	os.Exit(m.Run())
}

func TestUtility(t *testing.T) {
	c, err := NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(uid, password)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Health()
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Version()
	if err != nil {
		t.Fatal(err)
	}
}

func TestUserManagement(t *testing.T) {
	c, err := NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(uid, password)
	if err != nil {
		t.Fatal(err)
	}

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}

	createGroupResponse, err := c.CreateGroup(scopes)
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddUserToGroup(createUserResponse.UserID, createGroupResponse.GroupID)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemoveUserFromGroup(createUserResponse.UserID, createGroupResponse.GroupID)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemoveUser(createUserResponse.UserID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncrypt(t *testing.T) {
	c, err := NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(uid, password)
	if err != nil {
		t.Fatal(err)
	}

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := c.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	decryptResponse, err := c.Decrypt(encryptResponse.ObjectID, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	if err != nil {
		t.Fatal(err)
	}
	if string(decryptResponse.Plaintext) != string(plaintext) {
		t.Fatal("Decryption returned wrong plaintext")
	}
	if string(decryptResponse.AssociatedData) != string(associatedData) {
		t.Fatal("Decryption returned wrong data")
	}
}

func TestStore(t *testing.T) {
	c, err := NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(uid, password)
	if err != nil {
		t.Fatal(err)
	}

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := c.Store(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	retrieveResponse, err := c.Retrieve(storeResponse.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if string(retrieveResponse.Plaintext) != string(plaintext) {
		t.Fatal("Decryption returned wrong plaintext")
	}
	if string(retrieveResponse.AssociatedData) != string(associatedData) {
		t.Fatal("Decryption returned wrong data")
	}

	plaintext = []byte("foobar")
	associatedData = []byte("barbaz")
	err = c.Update(storeResponse.ObjectID, plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	err = c.Delete(storeResponse.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPermissions(t *testing.T) {
	c, err := NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(uid, password)
	if err != nil {
		t.Fatal(err)
	}

	createUserResponse, err := c.CreateUser(scopes)
	if err != nil {
		t.Fatal(err)
	}
	err = c.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := c.Store(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddPermission(storeResponse.ObjectID, createUserResponse.UserID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.GetPermissions(storeResponse.ObjectID)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemovePermission(storeResponse.ObjectID, createUserResponse.UserID)
	if err != nil {
		t.Fatal(err)
	}
}
