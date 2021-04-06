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
package objectstorage

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/gofrs/uuid"
	"net/http"

	"encryption-service/contextkeys"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

// Object store representing a connection to an S3 bucket
type ObjectStore struct {
	client *s3.S3
	bucket string
}

// Create a new object store defined by an endpoint and a bucket, authenticating with an access ID
// and key.
// Errors if the S3 session cannot be created.
func NewObjectStore(endpoint, bucket, accessID, accessKey string, cert []byte) (*ObjectStore, error) {
	rootCAs := x509.NewCertPool()

	if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
		return nil, errors.New("could not add object storage certificate to cert pool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	config := &aws.Config{
		HTTPClient:       client,
		Credentials:      credentials.NewStaticCredentials(accessID, accessKey, ""),
		Endpoint:         aws.String(endpoint),
		Region:           aws.String("europe-west-4"),
		S3ForcePathStyle: aws.Bool(true),
	}
	session, err := session.NewSession(config)
	if err != nil {
		return nil, err
	}

	return &ObjectStore{
		client: s3.New(session),
		bucket: bucket,
	}, nil
}

// Store an object under a given object ID
func (o *ObjectStore) Store(ctx context.Context, objectID string, object []byte) error {
	requestID, ok := ctx.Value(contextkeys.RequestIDCtxKey).(uuid.UUID)
	if !ok {
		return errors.New("Could not typecast requestID to uuid.UUID")
	}

	_, err := o.client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: &o.bucket,
		Key:    &objectID,
		Body:   bytes.NewReader(object),
	}, request.WithSetRequestHeaders(map[string]string{"Request-ID": requestID.String()}))
	return err
}

// Retrieve an object with a given object ID
func (o *ObjectStore) Retrieve(ctx context.Context, objectID string) ([]byte, error) {
	requestID, ok := ctx.Value(contextkeys.RequestIDCtxKey).(uuid.UUID)
	if !ok {
		return nil, errors.New("Could not typecast requestID to uuid.UUID")
	}

	getObjectOutput, err := o.client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: &o.bucket,
		Key:    &objectID,
	}, request.WithSetRequestHeaders(map[string]string{"Request-ID": requestID.String()}))
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(getObjectOutput.Body); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
