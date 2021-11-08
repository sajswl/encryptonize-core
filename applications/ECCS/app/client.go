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

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fullstorydev/grpcurl"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpc_reflection "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"

	"eccs/utils"
)

// Client for making test gRPC calls to the Encryptonize service
type Client struct {
	connection *grpc.ClientConn
	refClient  *grpcreflect.Client
	ctx        context.Context
	reflSource grpcurl.DescriptorSource
	authHeader []string
}

// NewClient creates a new client
// For a secure connection set the environment variable "ECCS_CRT" appropriately
func NewClient(userAT string) (*Client, error) {
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

	client := grpcreflect.NewClient(context.Background(), grpc_reflection.NewServerReflectionClient(connection))

	// Add metadata/credentials to context
	authHeader := []string{"authorization: bearer " + userAT}
	md := grpcurl.MetadataFromHeaders(authHeader)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	reflSource := grpcurl.DescriptorSourceFromServer(ctx, client)

	return &Client{
		connection: connection, // The grpc connection
		refClient:  client,     // The reflection client
		ctx:        ctx,        // The request context
		reflSource: reflSource, // The reflection source
		authHeader: authHeader, // The authorization header
	}, nil
}

func (c *Client) Invoke(method, input string) (string, error) {
	in := strings.NewReader(input)
	options := grpcurl.FormatOptions{
		EmitJSONDefaultFields: false,
		IncludeTextSeparator:  true,
		AllowUnknownFields:    false,
	}

	rf, formatter, err := grpcurl.RequestParserAndFormatter(grpcurl.Format("json"), c.reflSource, in, options)
	if err != nil {
		fmt.Print("Failed to construct request parser and formatter")
	}

	var response bytes.Buffer
	handler := &grpcurl.DefaultEventHandler{
		Out:            &response,
		Formatter:      formatter,
		VerbosityLevel: 0,
	}

	err = grpcurl.InvokeRPC(
		c.ctx,
		c.reflSource,
		c.connection,
		method,
		c.authHeader,
		handler,
		rf.Next)
	if err != nil {
		return "", err
	}

	return response.String(), nil
}

type Object struct {
	ObjectID string `json:"object_id"`
}

type Data struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associated_data"`
}

// Store calls the Encryptonize Store endpoint
func (c *Client) Store(plaintext, associatedData []byte) (string, error) {
	data, err := json.Marshal(Data{plaintext, associatedData})
	if err != nil {
		fmt.Print(err, "Failed to parse object data")
	}

	return c.Invoke("storage.Encryptonize.Store", string(data))
}

// Retrieve calls the Encryptonize Retrieve endpoint
func (c *Client) Retrieve(oid string) (string, error) {
	objectID, err := json.Marshal(Object{oid})
	if err != nil {
		fmt.Print(err, "Failed to parse object ID")
	}

	return c.Invoke("storage.Encryptonize.Retrieve", string(objectID))
}

// Update calls the Encryptonize Update endpoint
func (c *Client) Update(oid string, plaintext, associatedData []byte) (string, error) {
	object, err := json.Marshal(
		struct {
			ObjectID       string `json:"object_id"`
			Plaintext      []byte `json:"plaintext"`
			AssociatedData []byte `json:"associated_data"`
		}{
			ObjectID:       oid,
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		})
	if err != nil {
		fmt.Print(err, "Failed to parse object")
	}

	return c.Invoke("storage.Encryptonize.Update", string(object))
}

// Delete calls the Encryptonize Delete endpoint
func (c *Client) Delete(oid string) (string, error) {
	objectID, err := json.Marshal(Object{oid})
	if err != nil {
		fmt.Print(err, "Failed to parse object ID")
	}

	return c.Invoke("storage.Encryptonize.Delete", string(objectID))
}

// GetPermissions calls the Encryptonize GetPermissions endpoint
func (c *Client) GetPermissions(oid string) (string, error) {
	objectID, err := json.Marshal(Object{oid})
	if err != nil {
		fmt.Print(err, "Failed to parse object ID")
	}

	return c.Invoke("authz.Encryptonize.GetPermissions", string(objectID))
}

type UpdateType int

const (
	UpdateKindAdd = iota
	UpdateKindRemove
)

// UpdatePermissions either Adds a user to or Removes a user from the Access Object
// AddPermission and RemovePermission share the same signature so they are only
// distinguished by their name
func (c *Client) UpdatePermission(oid, target string, kind UpdateType) (string, error) {
	var method string
	switch kind {
	case UpdateKindAdd:
		method = "AddPermission"
	case UpdateKindRemove:
		method = "RemovePermission"
	default:
		return "", errors.New("Unknown update kind")
	}

	object, err := json.Marshal(
		struct {
			ObjectID string `json:"object_id"`
			UserID   string `json:"target"`
		}{
			ObjectID: oid,
			UserID:   target,
		})
	if err != nil {
		fmt.Print(err, "Failed to parse object ID")
	}

	return c.Invoke("authz.Encryptonize."+method, string(object))
}

func (c *Client) CreateUser(scopes []string) (string, error) {
	userScopes, err := json.Marshal(
		struct {
			UserScopes []string `json:"user_scopes"`
		}{
			UserScopes: scopes,
		})
	if err != nil {
		fmt.Print(err, "Failed to parse user scopes")
	}

	return c.Invoke("authn.Encryptonize.CreateUser", string(userScopes))
}

func (c *Client) LoginUser(uid, password string) (string, error) {
	credentials, err := json.Marshal(
		struct {
			UserID   string `json:"user_id"`
			Password string `json:"password"`
		}{
			UserID:   uid,
			Password: password,
		})
	if err != nil {
		fmt.Print(err, "Failed to parse credentials")
	}

	return c.Invoke("authn.Encryptonize.LoginUser", string(credentials))
}

func (c *Client) RemoveUser(uid string) (string, error) {
	user, err := json.Marshal(
		struct {
			UserID string `json:"user_id"`
		}{
			UserID: uid,
		})
	if err != nil {
		fmt.Print(err, "Failed to parse user id")
	}

	return c.Invoke("authn.Encryptonize.RemoveUser", string(user))
}

func (c *Client) Encrypt(plaintext, associatedData []byte) (string, error) {
	data, err := json.Marshal(Data{plaintext, associatedData})
	if err != nil {
		fmt.Print(err, "Failed to parse data")
	}

	return c.Invoke("enc.Encryptonize.Encrypt", string(data))
}

func (c *Client) Decrypt(oid string, ciphertext, associatedData []byte) (string, error) {
	object, err := json.Marshal(
		struct {
			ObjectID       string `json:"object_id"`
			Ciphertext     []byte `json:"ciphertext"`
			AssociatedData []byte `json:"associated_data"`
		}{
			ObjectID:       oid,
			Ciphertext:     ciphertext,
			AssociatedData: associatedData,
		})
	if err != nil {
		fmt.Print(err, "Failed to parse data")
	}

	return c.Invoke("enc.Encryptonize.Decrypt", string(object))
}
