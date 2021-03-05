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
package grpce2e

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"encryption-service/services/app"
	"encryption-service/services/authn"
	"encryption-service/services/enc"
	"encryption-service/users"
)

// Client for making test gRPC calls to the encryption service
type Client struct {
	connection *grpc.ClientConn
	appClient  app.EncryptonizeClient
	encClient  enc.EncryptonizeClient
	authClient authn.EncryptonizeClient
	ctx        context.Context
}

// Create a new client.
func NewClient(endpoint, token string, https bool) (*Client, error) {
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
	encClient := enc.NewEncryptonizeClient(connection)
	authClient := authn.NewEncryptonizeClient(connection)
	authMetadata := metadata.Pairs("authorization", fmt.Sprintf("bearer %v", token))
	ctx := metadata.NewOutgoingContext(context.Background(), authMetadata)

	return &Client{
		connection: connection,
		appClient:  appClient,
		encClient:  encClient,
		authClient: authClient,
		ctx:        ctx,
	}, nil
}

// Close the client connection. Call when done with the client.
func (c *Client) Close() error {
	err := c.connection.Close()
	return err
}

// Perform a `Store` request.
func (c *Client) Store(plaintext, associatedData []byte) (*enc.StoreResponse, error) {
	storeRequest := &enc.StoreRequest{
		Object: &enc.Object{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	}

	storeResponse, err := c.encClient.Store(c.ctx, storeRequest)
	if err != nil {
		return nil, fmt.Errorf("Store failed: %v", err)
	}
	return storeResponse, nil
}

// Perform a `Retrieve` request.
func (c *Client) Retrieve(oid string) (*enc.RetrieveResponse, error) {
	retrieveRequest := &enc.RetrieveRequest{ObjectId: oid}

	retrieveResponse, err := c.encClient.Retrieve(c.ctx, retrieveRequest)
	if err != nil {
		return nil, fmt.Errorf("Retrieve failed: %v", err)
	}
	return retrieveResponse, nil
}

// Perform a `GetPermissions` request.
func (c *Client) GetPermissions(oid string) (*enc.GetPermissionsResponse, error) {
	getPermissionsRequest := &enc.GetPermissionsRequest{ObjectId: oid}

	getPermissionsResponse, err := c.encClient.GetPermissions(c.ctx, getPermissionsRequest)
	if err != nil {
		return nil, fmt.Errorf("GetPermissions failed: %v", err)
	}
	return getPermissionsResponse, nil
}

// Perform a `AddPermission` request.
func (c *Client) AddPermission(oid, target string) (*enc.AddPermissionResponse, error) {
	addPermissionRequest := &enc.AddPermissionRequest{
		ObjectId: oid,
		Target:   target,
	}

	addPermissionResponse, err := c.encClient.AddPermission(c.ctx, addPermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("AddPermission failed: %v", err)
	}
	return addPermissionResponse, nil
}

// Perform a `RemovePermission` request.
func (c *Client) RemovePermission(oid, target string) (*enc.RemovePermissionResponse, error) {
	removePermissionRequest := &enc.RemovePermissionRequest{
		ObjectId: oid,
		Target:   target,
	}

	removePermissionResponse, err := c.encClient.RemovePermission(c.ctx, removePermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("RemovePermission failed: %v", err)
	}
	return removePermissionResponse, nil
}

// Perform a `CreateUser` request.
func (c *Client) CreateUser(userscopes []users.UserScope) (*authn.CreateUserResponse, error) {
	createUserRequest := &authn.CreateUserRequest{
		UserScopes: userscopes,
	}

	createUserResponse, err := c.authClient.CreateUser(c.ctx, createUserRequest)
	if err != nil {
		return nil, fmt.Errorf("CreateUser failed: %v", err)
	}
	return createUserResponse, nil
}

// Perform a `LoginUser` request.
func (c *Client) LoginUser(userid string, password string) (*authn.LoginUserResponse, error) {
	loginUserRequest := &authn.LoginUserRequest{
		UserId:   userid,
		Password: password,
	}

	loginUserResponse, err := c.authClient.LoginUser(c.ctx, loginUserRequest)
	if err != nil {
		return nil, fmt.Errorf("LoginUser failed: %v", err)
	}
	return loginUserResponse, nil
}

// Perform a `Version` request.
func (c *Client) GetVersion() (*app.VersionResponse, error) {
	versionResponse, err := c.appClient.Version(c.ctx, &app.VersionRequest{})

	if err != nil {
		return nil, fmt.Errorf("Get version failed: %v", err)
	}

	return versionResponse, err
}
