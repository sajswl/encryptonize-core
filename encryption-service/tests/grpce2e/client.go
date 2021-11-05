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
package grpce2e

import (
	"context"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"encryption-service/common"
	"encryption-service/services/app"
	"encryption-service/services/authn"
	"encryption-service/services/authz"
	"encryption-service/services/enc"
	"encryption-service/services/storage"
)

// Client for making test gRPC calls to the encryption service
type Client struct {
	connection    *grpc.ClientConn
	appClient     app.EncryptonizeClient
	storageClient storage.EncryptonizeClient
	encClient     enc.EncryptonizeClient
	authClient    authn.EncryptonizeClient
	authzClient   authz.EncryptonizeClient
	healthClient  grpc_health_v1.HealthClient
	ctx           context.Context
}

// Create a new client.
func NewClient(endpoint string, https bool) (*Client, error) {
	var dialOption grpc.DialOption

	if https {
		// Configure certificate
		clientCredentials, err := credentials.NewClientTLSFromFile("../../data/encryptonize.crt", "")
		if err != nil {
			return nil, err
		}
		dialOption = grpc.WithTransportCredentials(clientCredentials)
	} else {
		dialOption = grpc.WithInsecure()
	}

	connection, err := grpc.Dial(endpoint, dialOption)
	if err != nil {
		return nil, err
	}

	appClient := app.NewEncryptonizeClient(connection)
	storageClient := storage.NewEncryptonizeClient(connection)
	encClient := enc.NewEncryptonizeClient(connection)
	authClient := authn.NewEncryptonizeClient(connection)
	authzClient := authz.NewEncryptonizeClient(connection)
	healthClient := grpc_health_v1.NewHealthClient(connection)

	client := &Client{
		connection:    connection,
		appClient:     appClient,
		storageClient: storageClient,
		encClient:     encClient,
		authClient:    authClient,
		authzClient:   authzClient,
		healthClient:  healthClient,
		ctx:           context.Background(),
	}

	return client, nil
}

// Close the client connection. Call when done with the client.
func (c *Client) Close() error {
	err := c.connection.Close()
	return err
}

// SetToken sets the user access token for all future calls
func (c *Client) SetToken(token string) {
	authMetadata := metadata.Pairs("authorization", fmt.Sprintf("bearer %v", token))
	c.ctx = metadata.NewOutgoingContext(c.ctx, authMetadata)
}

// Perform a `Store` request.
func (c *Client) Store(plaintext, associatedData []byte) (*storage.StoreResponse, error) {
	storeRequest := &storage.StoreRequest{
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	}

	storeResponse, err := c.storageClient.Store(c.ctx, storeRequest)
	if err != nil {
		return nil, fmt.Errorf("Store failed: %v", err)
	}
	return storeResponse, nil
}

// Perform a `Retrieve` request.
func (c *Client) Retrieve(oid string) (*storage.RetrieveResponse, error) {
	retrieveRequest := &storage.RetrieveRequest{ObjectId: oid}

	retrieveResponse, err := c.storageClient.Retrieve(c.ctx, retrieveRequest)
	if err != nil {
		return nil, fmt.Errorf("Retrieve failed: %v", err)
	}
	return retrieveResponse, nil
}

func (c *Client) Update(oid string, plaintext, associatedData []byte) (*storage.UpdateResponse, error) {
	updateRequest := &storage.UpdateRequest{
		Plaintext:      plaintext,
		AssociatedData: associatedData,
		ObjectId:       oid,
	}

	updateResponse, err := c.storageClient.Update(c.ctx, updateRequest)
	if err != nil {
		return nil, fmt.Errorf("Update failed: %v", err)
	}
	return updateResponse, nil
}

// Perform a `Delete` request.
func (c *Client) Delete(oid string) (*storage.DeleteResponse, error) {
	deleteRequest := &storage.DeleteRequest{ObjectId: oid}

	deleteResponse, err := c.storageClient.Delete(c.ctx, deleteRequest)
	if err != nil {
		return nil, fmt.Errorf("Delete failed: %v", err)
	}
	return deleteResponse, nil
}

// Perform a `Encrypt` request.
func (c *Client) Encrypt(plaintext []byte, aad []byte) (*enc.EncryptResponse, error) {
	encryptRequest := &enc.EncryptRequest{
		Plaintext:      plaintext,
		AssociatedData: aad,
	}

	encryptResponse, err := c.encClient.Encrypt(c.ctx, encryptRequest)
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed: %v", err)
	}
	return encryptResponse, nil
}

// Perform a `Decrypt` request.
func (c *Client) Decrypt(ciphertext []byte, aad []byte, objectID string) (*enc.DecryptResponse, error) {
	decryptRequest := &enc.DecryptRequest{
		Ciphertext:     ciphertext,
		AssociatedData: aad,
		ObjectId:       objectID,
	}

	decryptResponse, err := c.encClient.Decrypt(c.ctx, decryptRequest)
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed: %v", err)
	}
	return decryptResponse, nil
}

// Perform a `GetPermissions` request.
func (c *Client) GetPermissions(oid string) (*authz.GetPermissionsResponse, error) {
	getPermissionsRequest := &authz.GetPermissionsRequest{ObjectId: oid}

	getPermissionsResponse, err := c.authzClient.GetPermissions(c.ctx, getPermissionsRequest)
	if err != nil {
		return nil, fmt.Errorf("GetPermissions failed: %v", err)
	}
	return getPermissionsResponse, nil
}

// Perform a `AddPermission` request.
func (c *Client) AddPermission(oid, target string) (*authz.AddPermissionResponse, error) {
	addPermissionRequest := &authz.AddPermissionRequest{
		ObjectId: oid,
		Target:   target,
	}

	addPermissionResponse, err := c.authzClient.AddPermission(c.ctx, addPermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("AddPermission failed: %v", err)
	}
	return addPermissionResponse, nil
}

// Perform a `RemovePermission` request.
func (c *Client) RemovePermission(oid, target string) (*authz.RemovePermissionResponse, error) {
	removePermissionRequest := &authz.RemovePermissionRequest{
		ObjectId: oid,
		Target:   target,
	}

	removePermissionResponse, err := c.authzClient.RemovePermission(c.ctx, removePermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("RemovePermission failed: %v", err)
	}
	return removePermissionResponse, nil
}

// Perform a `CreateUser` request.
func (c *Client) CreateUser(userscopes []common.Scope) (*authn.CreateUserResponse, error) {
	createUserRequest := &authn.CreateUserRequest{
		Scopes: userscopes,
	}

	createUserResponse, err := c.authClient.CreateUser(c.ctx, createUserRequest)
	if err != nil {
		return nil, fmt.Errorf("CreateUser failed: %v", err)
	}
	return createUserResponse, nil
}

// Perform a `LoginUser` request. This also sets the resulting access token in the client's context
// for all future calls.
func (c *Client) LoginUser(userid, password string) (*authn.LoginUserResponse, error) {
	loginUserRequest := &authn.LoginUserRequest{
		UserId:   userid,
		Password: password,
	}

	loginUserResponse, err := c.authClient.LoginUser(c.ctx, loginUserRequest)
	if err != nil {
		return nil, fmt.Errorf("LoginUser failed: %v", err)
	}

	c.SetToken(loginUserResponse.AccessToken)

	return loginUserResponse, nil
}

func (c *Client) RemoveUser(target string) (*authn.RemoveUserResponse, error) {
	removeUserRequest := &authn.RemoveUserRequest{
		UserId: target,
	}

	removeUserResponse, err := c.authClient.RemoveUser(c.ctx, removeUserRequest)
	if err != nil {
		return nil, fmt.Errorf("RemoveUser failed: %v", err)
	}
	return removeUserResponse, nil
}

// Perform a `Version` request.
func (c *Client) GetVersion() (*app.VersionResponse, error) {
	versionResponse, err := c.appClient.Version(c.ctx, &app.VersionRequest{})

	if err != nil {
		return nil, fmt.Errorf("Get version failed: %v", err)
	}

	return versionResponse, err
}

// HealthCheck performs a check to see if the server is alive
func (c *Client) HealthCheck() error {
	var err error
	var response *grpc_health_v1.HealthCheckResponse

	log.Println("Trying to ping server...")
	for i := 0; i < 120; i++ {
		response, err = c.healthClient.Check(c.ctx, &grpc_health_v1.HealthCheckRequest{})
		if err == nil && response.Status == grpc_health_v1.HealthCheckResponse_SERVING {
			log.Println("Server is alive!")
			return nil
		}

		time.Sleep(time.Second)
	}

	return err
}
