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

	"encryption-service/app"
)

// Client for making test gRPC calls to the encryption service
type Client struct {
	connection *grpc.ClientConn
	client     app.EncryptonizeClient
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

	client := app.NewEncryptonizeClient(connection)
	authMetadata := metadata.Pairs("authorization", token)
	ctx := metadata.NewOutgoingContext(context.Background(), authMetadata)

	return &Client{
		connection: connection,
		client:     client,
		ctx:        ctx,
	}, nil
}

// Close the client connection. Call when done with the client.
func (c *Client) Close() error {
	err := c.connection.Close()
	return err
}

// Perform a `Store` request.
func (c *Client) Store(plaintext, associatedData []byte) (*app.StoreResponse, error) {
	storeRequest := &app.StoreRequest{
		Object: &app.Object{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	}

	storeResponse, err := c.client.Store(c.ctx, storeRequest)
	if err != nil {
		return nil, fmt.Errorf("Store failed: %v", err)
	}
	return storeResponse, nil
}

// Perform a `Retrieve` request.
func (c *Client) Retrieve(oid string) (*app.RetrieveResponse, error) {
	retrieveRequest := &app.RetrieveRequest{ObjectId: oid}

	retrieveResponse, err := c.client.Retrieve(c.ctx, retrieveRequest)
	if err != nil {
		return nil, fmt.Errorf("Retrieve failed: %v", err)
	}
	return retrieveResponse, nil
}

// Perform a `GetPermissions` request.
func (c *Client) GetPermissions(oid string) (*app.GetPermissionsResponse, error) {
	getPermissionsRequest := &app.GetPermissionsRequest{ObjectId: oid}

	getPermissionsResponse, err := c.client.GetPermissions(c.ctx, getPermissionsRequest)
	if err != nil {
		return nil, fmt.Errorf("GetPermissions failed: %v", err)
	}
	return getPermissionsResponse, nil
}

// Perform a `AddPermission` request.
func (c *Client) AddPermission(oid, target string) (*app.AddPermissionResponse, error) {
	addPermissionRequest := &app.AddPermissionRequest{
		ObjectId: oid,
		Target:   target,
	}

	addPermissionResponse, err := c.client.AddPermission(c.ctx, addPermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("AddPermission failed: %v", err)
	}
	return addPermissionResponse, nil
}

// Perform a `RemovePermission` request.
func (c *Client) RemovePermission(oid, target string) (*app.RemovePermissionResponse, error) {
	removePermissionRequest := &app.RemovePermissionRequest{
		ObjectId: oid,
		Target:   target,
	}

	removePermissionResponse, err := c.client.RemovePermission(c.ctx, removePermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("RemovePermission failed: %v", err)
	}
	return removePermissionResponse, nil
}

// Perform a `CreateUser` request.
func (c *Client) CreateUser(userscopes []app.CreateUserRequest_UserScope) (*app.CreateUserResponse, error) {
	createUserRequest := &app.CreateUserRequest{
		UserScopes: userscopes,
	}

	createUserResponse, err := c.client.CreateUser(c.ctx, createUserRequest)
	if err != nil {
		return nil, fmt.Errorf("CreateUser failed: %v", err)
	}
	return createUserResponse, nil
}

// Perform a `Version` request.
func (c *Client) GetVersion() (*app.VersionResponse, error) {
	versionResponse, err := c.client.Version(c.ctx, &app.VersionRequest{})

	if err != nil {
		return nil, fmt.Errorf("Get version failed: %v", err)
	}

	return versionResponse, err
}
