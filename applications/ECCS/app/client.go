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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpc_reflection "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/types/descriptorpb"

	"eccs/utils"
)

// Client for making test gRPC calls to the Encryptonize service
type Client struct {
	connection *grpc.ClientConn
	refClient  *grpcreflect.Client
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

	client := grpcreflect.NewClient(context.Background(), grpc_reflection.NewServerReflectionClient(connection))

	// Add metadata/credetials to context
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	return &Client{
		connection: connection, // The grpc connection
		refClient:  client,     // The reflection client
		ctx:        ctx,        // The request context
	}, nil
}

// findMethod queries the grpc server via reflection to get a descriptor for some method
func (c *Client) findMethod(service, method string) (*desc.MethodDescriptor, error) {
	// resolve the service by name
	srvDes, err := c.refClient.ResolveService(service)
	if err != nil {
		return nil, err
	}

	// resolve the method of the service
	methDes := srvDes.FindMethodByName(method)
	if methDes == nil {
		errMsg := fmt.Sprintf("Service %s has no method named %s", service, method)
		return nil, errors.New(errMsg)
	}

	return methDes, nil
}

// sanitize asserts that a message has the specified fields
func sanitize(mt *desc.MessageDescriptor, ex map[string]descriptorpb.FieldDescriptorProto_Type) bool {
	fields := mt.GetFields()

	// make sure the message has exactly the number of fields we are expecting
	if len(fields) != len(ex) {
		return false
	}

	// look for each field we are expecting
	for name, exType := range ex {
		fd := mt.FindFieldByName(name)
		// assert it has the type we are expecting
		if fd == nil || fd.GetType() != exType {
			return false
		}
	}

	return true
}

// Store calls the Encryptonize Store endpoint
func (c *Client) Store(plaintext, associatedData []byte) (string, error) {
	mth, err := c.findMethod("storage.Encryptonize", "Store")
	if err != nil {
		return "", err
	}

	// sanitize in and output
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object": descriptorpb.FieldDescriptorProto_TYPE_MESSAGE,
	}
	if !sanitize(inType, inExp) {
		return "", errors.New("Unexpected input type of Store method")
	}

	objType := inType.FindFieldByName("object").GetMessageType()
	var objExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"plaintext":       descriptorpb.FieldDescriptorProto_TYPE_BYTES,
		"associated_data": descriptorpb.FieldDescriptorProto_TYPE_BYTES,
	}
	if !sanitize(objType, objExp) {
		return "", errors.New("Unexpected object type")
	}

	outType := mth.GetOutputType()
	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object_id": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(outType, outExp) {
		return "", errors.New("Unexpected type of the object message")
	}

	// create the object to be stored
	obj := dynamic.NewMessage(objType)
	obj.SetFieldByName("plaintext", plaintext)
	obj.SetFieldByName("associated_data", associatedData)

	// create the argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("object", obj)

	// invoke the RPC
	stub := grpcdynamic.NewStub(c.connection)
	pres, err := stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return "", err
	}

	// deconstruct the result
	res, err := dynamic.AsDynamicMessage(pres)
	if err != nil {
		return "", err
	}

	objID := res.GetFieldByName("object_id").(string)

	return objID, nil
}

// Retrieve calls the Encryptonize Retrieve endpoint
func (c *Client) Retrieve(oid string) ([]byte, []byte, error) {
	mth, err := c.findMethod("storage.Encryptonize", "Retrieve")
	if err != nil {
		return nil, nil, err
	}

	// sanitize input and output
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object_id": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(inType, inExp) {
		return nil, nil, errors.New("Unexpected input type of Retrieve method")
	}

	outType := mth.GetOutputType()
	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object": descriptorpb.FieldDescriptorProto_TYPE_MESSAGE,
	}
	if !sanitize(outType, outExp) {
		return nil, nil, errors.New("Unexpected output type of Retrieve method")
	}

	var objExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"plaintext":       descriptorpb.FieldDescriptorProto_TYPE_BYTES,
		"associated_data": descriptorpb.FieldDescriptorProto_TYPE_BYTES,
	}
	if !sanitize(outType.FindFieldByName("object").GetMessageType(), objExp) {
		return nil, nil, errors.New("Unexpected type of the object message")
	}

	// create argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("object_id", oid)

	// invoke RPC
	stub := grpcdynamic.NewStub(c.connection)
	pres, err := stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return nil, nil, err
	}

	// deconstruct result
	res, err := dynamic.AsDynamicMessage(pres)
	if err != nil {
		return nil, nil, err
	}

	obj := res.GetFieldByName("object").(*dynamic.Message)
	m := obj.GetFieldByName("plaintext").([]byte)
	aad := obj.GetFieldByName("associated_data").([]byte)

	return m, aad, nil
}

// GetPermissions calls the Encryptonize GetPermissions endpoint
func (c *Client) GetPermissions(oid string) ([]string, error) {
	mth, err := c.findMethod("storage.Encryptonize", "GetPermissions")
	if err != nil {
		return nil, err
	}

	// sanitzie input and output
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object_id": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(inType, inExp) {
		return nil, errors.New("Unexpected input type of GetPermissions method")
	}

	outType := mth.GetOutputType()
	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"user_ids": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(outType, outExp) {
		return nil, errors.New("Unexpected output type of GetPermissions method")
	}

	// create argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("object_id", oid)

	// invoke RPC
	stub := grpcdynamic.NewStub(c.connection)
	pres, err := stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return nil, err
	}

	// deconstruct result
	res, err := dynamic.AsDynamicMessage(pres)
	if err != nil {
		return nil, err
	}

	// collect repeated user_ids field
	idsField := outType.FindFieldByName("user_ids")
	numIds := res.FieldLength(idsField)
	var ids = []string{}
	for i := 0; i < numIds; i++ {
		ids = append(ids, res.GetRepeatedField(idsField, i).(string))
	}

	return ids, nil
}

type UpdateType int

const (
	UpdateKindAdd = iota
	UpdateKindRemove
)

// UpdatePermissions either Adds a user to or Removes a user from the Access Object
// AddPermission and RemovePermission share the same signature so they are only
// distinguished by their name
func (c *Client) UpdatePermission(oid, target string, kind UpdateType) error {
	var method string
	switch kind {
	case UpdateKindAdd:
		method = "AddPermission"
	case UpdateKindRemove:
		method = "RemovePermission"
	default:
		return errors.New("Unknown update kind")
	}

	mth, err := c.findMethod("storage.Encryptonize", method)
	if err != nil {
		return err
	}

	// sanitize input and output
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object_id": descriptorpb.FieldDescriptorProto_TYPE_STRING,
		"target":    descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(inType, inExp) {
		return errors.New("Unexpected input type of UpdatePermission method")
	}

	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{}
	if !sanitize(mth.GetOutputType(), outExp) {
		return errors.New("Unexpected output type of UpdatePermission method")
	}

	// create argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("object_id", oid)
	msg.SetFieldByName("target", target)

	// invoke RPC and disregard nonexisting return values
	stub := grpcdynamic.NewStub(c.connection)
	_, err = stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return err
	}

	return nil
}

// CreateUser calls the Encryptonize CreateUser endpoint
func (c *Client) CreateUser(scopes []string) (string, string, error) {
	mth, err := c.findMethod("authn.Encryptonize", "CreateUser")
	if err != nil {
		return "", "", err
	}

	// sanitize input and output
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"user_scopes": descriptorpb.FieldDescriptorProto_TYPE_ENUM,
	}
	if !sanitize(inType, inExp) {
		return "", "", errors.New("Unexpected input type of CreateUser method")
	}

	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"user_id":  descriptorpb.FieldDescriptorProto_TYPE_STRING,
		"password": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(mth.GetOutputType(), outExp) {
		return "", "", errors.New("Unexpected output type of CreateUser method")
	}

	// create a map to translate the scope names to the enum
	scopeField := inType.FindFieldByName("user_scopes")
	scopeMap := make(map[string]int32)
	for _, e := range scopeField.GetEnumType().GetValues() {
		scopeMap[e.GetName()] = e.GetNumber()
		log.Printf("%s: %v", e.GetName(), e.GetNumber())
	}

	// create argument
	msg := dynamic.NewMessage(inType)
	for _, scope := range scopes {
		msg.AddRepeatedField(scopeField, scopeMap[scope])
	}

	// invoke RPC
	stub := grpcdynamic.NewStub(c.connection)
	pres, err := stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return "", "", err
	}

	// deconstruct return value
	res, err := dynamic.AsDynamicMessage(pres)
	if err != nil {
		return "", "", err
	}

	uid := res.GetFieldByName("user_id").(string)
	password := res.GetFieldByName("password").(string)

	return uid, password, nil
}

func (c *Client) LoginUser(uid, password string) (string, error) {
	mth, err := c.findMethod("authn.Encryptonize", "LoginUser")
	if err != nil {
		return "", err
	}

	// sanitize input and outputs
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"user_id":  descriptorpb.FieldDescriptorProto_TYPE_STRING,
		"password": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(inType, inExp) {
		return "", errors.New("Unexpected input type of LoginUser method")
	}

	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"access_token": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}

	if !sanitize(mth.GetOutputType(), outExp) {
		return "", errors.New("Unexpected output type of LoginUser method")
	}

	// create argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("user_id", uid)
	msg.SetFieldByName("password", password)

	// invoke RPC
	stub := grpcdynamic.NewStub(c.connection)
	pres, err := stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return "", err
	}

	// deconstruct return value
	res, err := dynamic.AsDynamicMessage(pres)
	if err != nil {
		return "", err
	}

	at := res.GetFieldByName("access_token").(string)

	return at, nil
}

func (c *Client) RemoveUser(uid string) error {
	mth, err := c.findMethod("authn.Encryptonize", "RemoveUser")
	if err != nil {
		return err
	}

	// sanitize input and outputs
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"user_id": descriptorpb.FieldDescriptorProto_TYPE_STRING,
	}
	if !sanitize(inType, inExp) {
		return errors.New("Unexpected input type of RemoveUser method")
	}

	var outExp = map[string]descriptorpb.FieldDescriptorProto_Type{}
	if !sanitize(mth.GetOutputType(), outExp) {
		return errors.New("Unexpected output type of RemoveUser method")
	}

	// create argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("user_id", uid)

	// invoke RPC and disregard nonexisting return values
	stub := grpcdynamic.NewStub(c.connection)
	_, err = stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Encrypt(plaintext, associatedData []byte) (string, []byte, []byte, error) {
	mth, err := c.findMethod("enc.Encryptonize", "Encrypt")
	if err != nil {
		return "", nil, nil, err
	}

	// sanitize in and output
	inType := mth.GetInputType()
	var inExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"object": descriptorpb.FieldDescriptorProto_TYPE_MESSAGE,
	}
	if !sanitize(inType, inExp) {
		return "", nil, nil, errors.New("Unexpected input type of Encrypt method")
	}

	objType := inType.FindFieldByName("object").GetMessageType()
	var objExp = map[string]descriptorpb.FieldDescriptorProto_Type{
		"plaintext":       descriptorpb.FieldDescriptorProto_TYPE_BYTES,
		"associated_data": descriptorpb.FieldDescriptorProto_TYPE_BYTES,
	}
	if !sanitize(objType, objExp) {
		return "", nil, nil, errors.New("Unexpected object type")
	}

	// create the object to be stored
	obj := dynamic.NewMessage(objType)
	obj.SetFieldByName("plaintext", plaintext)
	obj.SetFieldByName("associated_data", associatedData)

	// create the argument
	msg := dynamic.NewMessage(inType)
	msg.SetFieldByName("object", obj)

	// invoke the RPC
	stub := grpcdynamic.NewStub(c.connection)
	pres, err := stub.InvokeRpc(c.ctx, mth, msg)
	if err != nil {
		return "", nil, nil, err
	}

	// deconstruct the result
	res, err := dynamic.AsDynamicMessage(pres)
	if err != nil {
		return "", nil, nil, err
	}

	objID := res.GetFieldByName("object_id").(string)

	ciphertext := res.GetFieldByName("ciphertext").([]byte)
	aad := obj.GetFieldByName("associated_data").([]byte)

	return objID, ciphertext, aad, nil
}

// func (c *Client) Decrypt() {
// 	mth, err := c.findMethod("enc.Encryptonize", "Decrypt")
// }
