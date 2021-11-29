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

package client

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClientWR for making gRPC calls to the Encryptonize service while automatically refreshing the
// access token.
type ClientWR struct { //nolint:revive
	Client
	uid      string
	password string
}

// NewClientWR creates a new Encryptonize client. In order to switch credentials to another user,
// use `LoginUser`.
func NewClientWR(ctx context.Context, endpoint, certPath, uid, password string) (*ClientWR, error) {
	client, err := NewClient(ctx, endpoint, certPath)
	if err != nil {
		return nil, err
	}

	err = client.LoginUser(uid, password)
	if err != nil {
		return nil, err
	}

	return &ClientWR{
		Client:   *client,
		uid:      uid,
		password: password,
	}, nil
}

// withRefresh calls `call`. In case the access token appears to be expired, it will try to refresh
// the token, and then try to call `call` again.
func (c *ClientWR) withRefresh(call func() error) error {
	err := call()
	if errStatus, _ := status.FromError(err); errStatus.Code() == codes.Unauthenticated {
		err := c.Client.LoginUser(c.uid, c.password)
		if err != nil {
			return err
		}
		return call()
	}
	return err
}

/////////////////////////////////////////////////////////////////////////
//                               Utility                               //
/////////////////////////////////////////////////////////////////////////

// Version retrieves the version information of the Encryptonize service.
func (c *ClientWR) Version() (*VersionResponse, error) {
	var response *VersionResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.Version()
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Health retrieves the current health status of the Encryptonize service.
func (c *ClientWR) Health() (*HealthResponse, error) {
	var response *HealthResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.Health()
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

/////////////////////////////////////////////////////////////////////////
//                           User Management                           //
/////////////////////////////////////////////////////////////////////////

// LoginUser authenticates to the Encryptonize service with the given credentials and sets the
// resulting access token for future calls. Call `LoginUser` again to switch to a different user.
func (c *ClientWR) LoginUser(uid, password string) error {
	err := c.Client.LoginUser(uid, password)
	if err != nil {
		return err
	}
	c.uid = uid
	c.password = password
	return nil
}

// CreateUser creates a new Encryptonize user with the requested scopes.
func (c *ClientWR) CreateUser(scopes []Scope) (*CreateUserResponse, error) {
	var response *CreateUserResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.CreateUser(scopes)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// RemoveUser removes a user from the Encryptonize service.
func (c *ClientWR) RemoveUser(uid string) error {
	return c.withRefresh(func() error {
		return c.Client.RemoveUser(uid)
	})
}

// CreateGroup creates a new Encryptonize group with the requested scopes.
func (c *ClientWR) CreateGroup(scopes []Scope) (*CreateGroupResponse, error) {
	var response *CreateGroupResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.CreateGroup(scopes)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// AddUserToGroup adds a user to a group.
func (c *ClientWR) AddUserToGroup(uid, gid string) error {
	return c.withRefresh(func() error {
		return c.Client.AddUserToGroup(uid, gid)
	})
}

// RemoveUserFromGroup removes a user from a group.
func (c *ClientWR) RemoveUserFromGroup(uid, gid string) error {
	return c.withRefresh(func() error {
		return c.Client.RemoveUserFromGroup(uid, gid)
	})
}

/////////////////////////////////////////////////////////////////////////
//                              Encryption                             //
/////////////////////////////////////////////////////////////////////////

// Encrypt encrypts the `plaintext` and tags both `plaintext` and `associatedData` returning the
// resulting ciphertext.
func (c *ClientWR) Encrypt(plaintext, associatedData []byte) (*EncryptResponse, error) {
	var response *EncryptResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.Encrypt(plaintext, associatedData)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Decrypt decrypts a previously encrypted `ciphertext` and verifies the integrity of the `ciphertext`
// and `associatedData`.
func (c *ClientWR) Decrypt(objectID string, ciphertext, associatedData []byte) (*DecryptResponse, error) {
	var response *DecryptResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.Decrypt(objectID, ciphertext, associatedData)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

/////////////////////////////////////////////////////////////////////////
//                               Storage                               //
/////////////////////////////////////////////////////////////////////////

// Store encrypts the `plaintext` and tags both `plaintext` and `associatedData` storing the
// resulting ciphertext in the Encryptonize service.
func (c *ClientWR) Store(plaintext, associatedData []byte) (*StoreResponse, error) {
	var response *StoreResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.Store(plaintext, associatedData)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Retrieve decrypts a previously stored object returning the ciphertext.
func (c *ClientWR) Retrieve(oid string) (*RetrieveResponse, error) {
	var response *RetrieveResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.Retrieve(oid)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Update replaces the currently stored data of an object with the specified `plaintext` and
// `associatedData`.
func (c *ClientWR) Update(oid string, plaintext, associatedData []byte) error {
	return c.withRefresh(func() error {
		return c.Client.Update(oid, plaintext, associatedData)
	})
}

// Delete removes previously stored data from the Encryptonize service.
func (c *ClientWR) Delete(oid string) error {
	return c.withRefresh(func() error {
		return c.Client.Delete(oid)
	})
}

/////////////////////////////////////////////////////////////////////////
//                             Permissions                             //
/////////////////////////////////////////////////////////////////////////

// GetPermissions returns a list of IDs that have access to the requested object.
func (c *ClientWR) GetPermissions(oid string) (*GetPermissionsResponse, error) {
	var response *GetPermissionsResponse
	err := c.withRefresh(func() error {
		var err error
		response, err = c.Client.GetPermissions(oid)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// AddPermission grants permission for the `target` to the requested object.
func (c *ClientWR) AddPermission(oid, target string) error {
	return c.withRefresh(func() error {
		return c.Client.AddPermission(oid, target)
	})
}

// RemovePermission removes permissions for the `target` to the requested object.
func (c *ClientWR) RemovePermission(oid, target string) error {
	return c.withRefresh(func() error {
		return c.Client.RemovePermission(oid, target)
	})
}
