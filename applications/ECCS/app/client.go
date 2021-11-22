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
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fullstorydev/grpcurl"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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

	// Define context
	ctx := context.Background()

	// Initialize connection with Encryptonize server
	connection, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	client := grpcreflect.NewClient(ctx, grpc_reflection.NewServerReflectionClient(connection))
	reflSource := grpcurl.DescriptorSourceFromServer(ctx, client)
	authHeader := []string{"authorization: bearer " + userAT}

	return &Client{
		connection: connection, // The grpc connection
		refClient:  client,     // The reflection client
		ctx:        ctx,        // The request context
		reflSource: reflSource, // The reflection source
		authHeader: authHeader, // The authorization header
	}, nil
}

// Invoke invokes given method on a gRPC channel
func (c *Client) Invoke(method, input string) (string, error) {
	in := strings.NewReader(input)
	options := grpcurl.FormatOptions{
		EmitJSONDefaultFields: false,
		IncludeTextSeparator:  true,
		AllowUnknownFields:    false,
	}

	rf, formatter, err := grpcurl.RequestParserAndFormatter(grpcurl.FormatJSON, c.reflSource, in, options)
	if err != nil {
		return "", fmt.Errorf("%v: %v", utils.Fail("Failed to construct request parser and formatter"), err)
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
		return "", fmt.Errorf("%v: %v", utils.Fail("Failed to invoke RPC"), err)
	}
	if handler.Status.Code() != codes.OK {
		return "", fmt.Errorf("%v: %v", utils.Fail("Request rejected by Encryptonize"), handler.Status.Message())
	}

	return response.String(), nil
}

// Store calls the Encryptonize Store endpoint
func (c *Client) Store(filename, associatedData string, stdin bool) error {
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Store failed"), err)
	}

	data, err := json.Marshal(Data{plaintext, []byte(associatedData)})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse data"), err)
	}

	response, err := c.Invoke("storage.Encryptonize.Store", string(data))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Store failed"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully stored object!"), response)

	return nil
}

// Retrieve calls the Encryptonize Retrieve endpoint
func (c *Client) Retrieve(oid string) error {
	objectID, err := json.Marshal(Object{oid})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse object ID"), err)
	}

	response, err := c.Invoke("storage.Encryptonize.Retrieve", string(objectID))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Retrieve failed"), err)
	}

	var data RetrievedData
	err = json.Unmarshal([]byte(response), &data)
	if err != nil {
		return fmt.Errorf("Provided input does not contain the required structure")
	}

	retrieved, err := json.Marshal(DecodedRetrievedData{Plaintext: string(data.Plaintext), AssociatedData: string(data.AssociatedData)})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to decode retrieved data"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully retrieved object!"), retrieved)

	return nil
}

// Update calls the Encryptonize Update endpoint
func (c *Client) Update(oid, filename, associatedData string, stdin bool) error {
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		return fmt.Errorf("Failed to read input from file")
	}

	updateObject, err := json.Marshal(UpdateObject{oid, plaintext, []byte(associatedData)})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse update object"), err)
	}

	_, err = c.Invoke("storage.Encryptonize.Update", string(updateObject))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Update failed"), err)
	}

	log.Printf("%v\n", utils.Pass("Successfully updated object!"))

	return nil
}

// Delete calls the Encryptonize Delete endpoint
func (c *Client) Delete(oid string) error {
	objectID, err := json.Marshal(Object{oid})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse object ID"), err)
	}

	_, err = c.Invoke("storage.Encryptonize.Delete", string(objectID))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("RemoveUser failed"), err)
	}

	log.Printf("%v\n", utils.Pass("Successfully deleted object!"))

	return nil
}

// GetPermissions calls the Encryptonize GetPermissions endpoint
func (c *Client) GetPermissions(oid string) error {
	objectID, err := json.Marshal(Object{oid})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse object ID"), err)
	}

	response, err := c.Invoke("authz.Encryptonize.GetPermissions", string(objectID))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("RemoveUser failed"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully got permissions!"), response)

	return nil
}

// AddPermission calls the Encryptonize AddPermission endpoint
func (c *Client) AddPermission(oid, target string) error {
	object, err := json.Marshal(ObjectPermissions{oid, target})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse object permissions"), err)
	}

	_, err = c.Invoke("authz.Encryptonize.AddPermission", string(object))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("AddPermission failed"), err)
	}

	log.Printf("%v\n", utils.Pass("Successfully added permissions!"))

	return nil
}

// RemovePermission calls the Encryptonize RemovePermission endpoint
func (c *Client) RemovePermission(oid, target string) error {
	object, err := json.Marshal(ObjectPermissions{oid, target})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse object permissions"), err)
	}

	_, err = c.Invoke("authz.Encryptonize.RemovePermission", string(object))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("RemovePermission failed"), err)
	}

	log.Printf("%v\n", utils.Pass("Successfully removed permissions!"))

	return nil
}

// CreateUser calls the Encryptonize CreateUser endpoint
func (c *Client) CreateUser(userScope Scope) error {
	// Encryptonize expects user type to be of type []CreateUserRequest_UserScope
	var scopes = []string{}

	if userScope.Read {
		scopes = append(scopes, "READ")
	}
	if userScope.Create {
		scopes = append(scopes, "CREATE")
	}
	if userScope.Update {
		scopes = append(scopes, "UPDATE")
	}
	if userScope.Delete {
		scopes = append(scopes, "DELETE")
	}
	if userScope.Index {
		scopes = append(scopes, "INDEX")
	}
	if userScope.ObjectPermissions {
		scopes = append(scopes, "OBJECTPERMISSIONS")
	}
	if userScope.UserManagement {
		scopes = append(scopes, "USERMANAGEMENT")
	}

	if len(scopes) < 1 {
		log.Fatalf("%v: At least a single scope is required", utils.Fail("CreateUser failed"))
	}

	userScopes, err := json.Marshal(Scopes{scopes})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse user scopes"), err)
	}

	response, err := c.Invoke("authn.Encryptonize.CreateUser", string(userScopes))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("CreateUser failed"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully created user!"), response)

	return nil
}

// LoginUser calls the Encryptonize LoginUser endpoint
func (c *Client) LoginUser(uid, password string) error {
	credentials, err := json.Marshal(Credentials{uid, password})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse credentials"), err)
	}

	response, err := c.Invoke("authn.Encryptonize.LoginUser", string(credentials))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("LoginUser failed"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully logged in user!"), response)

	return nil
}

// RemoveUser calls the Encryptonize RemoveUser endpoint
func (c *Client) RemoveUser(uid string) error {
	user, err := json.Marshal(User{uid})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse user id"), err)
	}

	_, err = c.Invoke("authn.Encryptonize.RemoveUser", string(user))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("RemoveUser failed"), err)
	}

	log.Printf("%v\n", utils.Pass("Successfully removed user!"))

	return nil
}

// CreateGroup calls the Encryptonize CreateGroup endpoint
func (c *Client) CreateGroup(groupScope Scope) error {
	var scopes = []string{}

	if groupScope.Read {
		scopes = append(scopes, "READ")
	}
	if groupScope.Create {
		scopes = append(scopes, "CREATE")
	}
	if groupScope.Update {
		scopes = append(scopes, "UPDATE")
	}
	if groupScope.Delete {
		scopes = append(scopes, "DELETE")
	}
	if groupScope.Index {
		scopes = append(scopes, "INDEX")
	}
	if groupScope.ObjectPermissions {
		scopes = append(scopes, "OBJECTPERMISSIONS")
	}
	if groupScope.UserManagement {
		scopes = append(scopes, "USERMANAGEMENT")
	}

	if len(scopes) < 1 {
		log.Fatalf("%v: At least a single scope is required", utils.Fail("CreateGroup failed"))
	}

	groupScopes, err := json.Marshal(Scopes{scopes})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse group scopes"), err)
	}

	response, err := c.Invoke("authn.Encryptonize.CreateGroup", string(groupScopes))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("CreateGroup failed"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully created group!"), response)

	return nil
}

// Encrypt calls the Encryptonize Encrypt endpoint
func (c *Client) Encrypt(filename, associatedData string, stdin bool) error {
	plaintext, err := readInput(filename, stdin)
	if err != nil {
		return fmt.Errorf("Failed to read input from file")
	}

	data, err := json.Marshal(Data{plaintext, []byte(associatedData)})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse data"), err)
	}

	response, err := c.Invoke("enc.Encryptonize.Encrypt", string(data))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Encrypt failed"), err)
	}

	// Log status to logging output
	log.Printf("%v\n", utils.Pass("Successfully encrypted object!"))

	// Output actual output to stdout
	fmt.Printf("%s\n", response)

	return nil
}

// Decrypt calls the Encryptonize Decrypt endpoint
func (c *Client) Decrypt(filename string, stdin bool) error {
	var enc DecodedEncryptedData
	storedData, err := readInput(filename, stdin)
	if err != nil {
		return fmt.Errorf("Failed to read input from file")
	}

	err = json.Unmarshal(storedData, &enc)
	if err != nil {
		return fmt.Errorf("Provided input does not contain the required structure")
	}

	decodedCiphertext, err := b64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return fmt.Errorf("Failed to decode ciphertext")
	}

	decodedAAD, err := b64.StdEncoding.DecodeString(enc.AssociatedData)
	if err != nil {
		return fmt.Errorf("Failed to decode associated data")
	}

	encryptedData, err := json.Marshal(EncryptedData{decodedCiphertext, decodedAAD, enc.ObjectID})
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Failed to parse data"), err)
	}

	response, err := c.Invoke("enc.Encryptonize.Decrypt", string(encryptedData))
	if err != nil {
		return fmt.Errorf("%v: %v", utils.Fail("Decrypt failed"), err)
	}

	log.Printf("%v\n%s", utils.Pass("Successfully decrypted object!"), response)

	return nil
}

// readInput reads bytes from provided filename, or from stdin
// Exits program if both are provided
func readInput(filename string, stdin bool) ([]byte, error) {
	var plaintext []byte

	if filename != "" && stdin {
		return nil, errors.New("can't take both filename and stdin")
	}
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			log.Fatalf("%v: %v", utils.Fail("Open file failed"), err)
		}
		plaintext = data
	}
	if stdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		plaintext = data
	}

	return plaintext, nil
}
