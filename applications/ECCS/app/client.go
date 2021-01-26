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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"eccs/utils"
	"eccs/authn"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Client for making test gRPC calls to the Encryptonize service
type Client struct {
	connection *grpc.ClientConn
	appClient  EncryptonizeClient
	authClient authn.EncryptonizeClient
	ctx        context.Context
}

// NewClient creates a new client
// For a secure connection set the environment variable "ECCS_CRT" appropriately
func NewClient(userAT string) (*Client, error) {
	// Wrap credentials as gRPC metadata
	md := metadata.Pairs("authorization", fmt.Sprintf("bearer %s", userAT)) // set authorization header

	// Get endpoint from env var
	endpoint, ok := os.LookupEnv("ECCS_ENDPOINT") // Fetch endpoint, note that the service is running on port 9000
	if !ok {
		return nil, fmt.Errorf("%v No endpoint specified, set it as env var ECCS_ENDPOINT", utils.Fail("Client creation failed:"))
	}

	var opts []grpc.DialOption
	crt, ok := os.LookupEnv("ECCS_CRT") // Fetch the tls certificate of the remote host
	if !ok {
		// If the environment is unset assume tls not to be used
		opts = append(opts, grpc.WithInsecure())
	} else {
		var tlsConf tls.Config
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("%v Unable to open system certificate pool", utils.Fail("Client creation failed:"))
		}

		if crt == "insecure" {
			tlsConf.InsecureSkipVerify = true
		} else if crt != "" {
			// extract the certificate from the environment variable and add it to the certificate pool
			ok := pool.AppendCertsFromPEM([]byte(crt))
			if !ok {
				return nil, fmt.Errorf("%v Unable to add certificate from ECCS_CRT to the certificate pool. Make sure it is a PEM certificate and not a file containing one", utils.Fail("Client creation failed:"))
			}
		}

		// if the environment variable is empty, assume they have a valid certificate from some CA
		tlsConf.RootCAs = pool
		creds := credentials.NewTLS(&tlsConf)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	// Initialize connection with Encryptonize server
	connection, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	// Create client
	appClient := NewEncryptonizeClient(connection)
	authClient := authn.NewEncryptonizeClient(connection)

	// Add metadata/credetials to context
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	return &Client{
		connection: connection, // The grpc connection
		appClient:  appClient,  // The client generated to the grpc stubs
		authClient: authClient, 
		ctx:        ctx,        // The request context
	}, nil
}

// Store calls the Encryptonize Store endpoint
func (c *Client) Store(plaintext, associatedData []byte) (*StoreResponse, error) {
	// Define request struct
	storeRequest := &StoreRequest{
		Object: &Object{
			Plaintext:      plaintext,      // The plaintext to be encrypted and afterwards stored
			AssociatedData: associatedData, // Some associated data to be stored along with the encrypted plain text, note that this isn't encrypted
		},
	}

	// Make the actual gRPC call
	storeResponse, err := c.appClient.Store(c.ctx, storeRequest)
	if err != nil {
		return nil, fmt.Errorf("Store failed: %v", err)
	}
	return storeResponse, nil
}

// Retrieve calls the Encryptonize Retrieve endpoint
func (c *Client) Retrieve(oid string) (*RetrieveResponse, error) {
	// Define request struct
	retrieveRequest := &RetrieveRequest{ObjectId: oid} // Construct the retrieve request. This only requires the object id of the object to be fetched from storage.

	// Make the actual gRPC call
	retrieveResponse, err := c.appClient.Retrieve(c.ctx, retrieveRequest)
	if err != nil {
		return nil, fmt.Errorf("Retrieve failed: %v", err)
	}
	return retrieveResponse, nil
}

// GetPermissions calls the Encryptonize GetPermissions endpoint
func (c *Client) GetPermissions(oid string) (*GetPermissionsResponse, error) {
	// Define request struct
	getPermissionsRequest := &GetPermissionsRequest{ObjectId: oid} // Construct the GetPermissions request. This only requires the object id of the object.

	// Make the actual gRPC call
	getPermissionsResponse, err := c.appClient.GetPermissions(c.ctx, getPermissionsRequest)
	if err != nil {
		return nil, fmt.Errorf("GetPermissions failed: %v", err)
	}
	return getPermissionsResponse, nil
}

// AddPermission calls the Encryptonize AddPermission endpoint
func (c *Client) AddPermission(oid, target string) (*AddPermissionResponse, error) {
	// Define request struct
	addPermissionRequest := &AddPermissionRequest{ObjectId: oid, Target: target} // Construct the AddPermission request.

	// Make the actual gRPC call
	addPermissionResponse, err := c.appClient.AddPermission(c.ctx, addPermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("AddPermission failed: %v", err)
	}
	return addPermissionResponse, nil
}

// RemovePermission calls the Encryptonize RemovePermission endpoint
func (c *Client) RemovePermission(oid, target string) (*RemovePermissionResponse, error) {
	// Define request struct
	removePermissionRequest := &RemovePermissionRequest{ObjectId: oid, Target: target} // Construct the RemovePermission request.

	// Make the actual gRPC call
	removePermissionResponse, err := c.appClient.RemovePermission(c.ctx, removePermissionRequest)
	if err != nil {
		return nil, fmt.Errorf("RemovePermission failed: %v", err)
	}
	return removePermissionResponse, nil
}

// CreateUser calls the Encryptonize CreateUser endpoint
func (c *Client) CreateUser(scopes []authn.UserScope) (*authn.CreateUserResponse, error) {
	// Define request struct
	createUserRequest := &authn.CreateUserRequest{UserScopes: scopes} // Construct the CreateUser request. This only requires the user list of scopes the user is granted.

	// Make the actual gRPC call
	createUserResponse, err := c.authClient.CreateUser(c.ctx, createUserRequest)
	if err != nil {
		return nil, fmt.Errorf("CreateUser failed: %v", err)
	}
	return createUserResponse, nil
}
