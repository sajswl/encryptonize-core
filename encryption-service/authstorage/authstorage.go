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
package authstorage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgtype"
	pgtypeuuid "github.com/jackc/pgtype/ext/gofrs-uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/sony/gobreaker"

	"encryption-service/contextkeys"
	log "encryption-service/logger"
)

// Interface representing a connection to the Auth Store
type AuthStoreInterface interface {
	NewTransaction(ctx context.Context) (AuthStoreTxInterface, error)
	Close()
}

// Interface representing a transaction on the Auth Store
type AuthStoreTxInterface interface {
	Rollback(ctx context.Context) error
	Commit(ctx context.Context) error

	// User handling
	GetUser(ctx context.Context, userID uuid.UUID) ([]byte, error)
	UpsertUser(ctx context.Context, userID uuid.UUID) error

	// Access Object handling
	GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error)
	InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
	UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
}

// TODO: Tune circuit breaker
// The circuit breaker helps to prevent unnecessary connections towards the auth storage
// to connect while in the "closed" state. If the circuit breaker reaches a failure ratio high enough,
// it switches to the "open" state, and connections to the auth store are no longer made.
// More details on circuit breaker pattern: https://docs.microsoft.com/en-us/previous-versions/msp-n-p/dn589784(v=pandp.10)?redirectedfrom=MSDN
func initCircuitBreaker() *gobreaker.CircuitBreaker {
	st := gobreaker.Settings{ // Default implementation lets the circuit breaker trip on 5 consecutive failure. For custom behaviour set "ReadyToTrip" function.
		Name:        "Auth storage connection",
		MaxRequests: 1,                               // Allow only 1 request in "half-opened" state
		Timeout:     time.Duration(60) * time.Second, // Time to wait in the "open" state
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			msg := fmt.Sprintf("Circuitbreaker %s has changed state from %v to %v", name, from, to)
			log.Info(context.TODO(), msg)
		},
	}

	return gobreaker.NewCircuitBreaker(st)
}

// ErrNoRows : Return this error when an empty record set is returned for the DB
// e.g. when a users isn't found
var ErrNoRows = errors.New("no rows in result set")
var cb *gobreaker.CircuitBreaker = initCircuitBreaker()

// Implementation of the AuthStoreInterface
type AuthStore struct {
	pool *pgxpool.Pool
}

// Implementation of AuthStoreTxInterface
type AuthStoreTx struct {
	tx        pgx.Tx
	requestID uuid.UUID
}

// NewAuthStore creates a new DB pool for the DB URL (postgresql://...).
// Additionally, it configures the pool to use `gofrs-uuid` for handling UUIDs.
// TODO: configure connection pool (min, max connections etc.)
func NewAuthStore(ctx context.Context, URL string) (*AuthStore, error) {
	config, err := pgxpool.ParseConfig(URL)
	if err != nil {
		return nil, err
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		conn.ConnInfo().RegisterDataType(pgtype.DataType{
			Value: &pgtypeuuid.UUID{},
			Name:  "uuid",
			OID:   pgtype.UUIDOID,
		})
		return nil
	}
	config.LazyConnect = true                                                 // Don't need to connect immediately
	config.ConnConfig.Config.ConnectTimeout = time.Duration(10) * time.Second // If we cannot connect in 10 seconds, then we most likely cannot connect at all
	pool, err := pgxpool.ConnectConfig(ctx, config)

	if err != nil {
		return nil, err
	}
	return &AuthStore{pool: pool}, nil
}

// NewTransaction starts a new Transaction (tx) in the pool and instances an AuthStoreTx with it
func (store *AuthStore) NewTransaction(ctx context.Context) (AuthStoreTxInterface, error) {
	// Wrap DB connection in a circuit breaker. By default, it trips to "open" state after 5 consecutive failures.
	tx, err := cb.Execute(func() (interface{}, error) {
		tx, err := store.pool.Begin(ctx)

		if err != nil {
			return nil, err
		}

		return tx, err
	})

	if err != nil {
		return nil, err
	}

	requestID, ok := ctx.Value(contextkeys.RequestIDCtxKey).(uuid.UUID)
	if !ok {
		return nil, errors.New("Could not typecast requestID to uuid.UUID")
	}

	authStorage := &AuthStoreTx{
		tx:        tx.(pgx.Tx),
		requestID: requestID,
	}

	return authStorage, nil
}

func (store *AuthStore) Close() {
	store.pool.Close()
}

// Used as a defer function to rollback an unfinished transaction
func (storeTx *AuthStoreTx) Rollback(ctx context.Context) error {
	err := storeTx.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Commit commits the encapsulated transcation
func (storeTx *AuthStoreTx) Commit(ctx context.Context) error {
	return storeTx.tx.Commit(ctx)
}

// Enriches the query with request id for tracing to the SQL audit log
func (storeTx *AuthStoreTx) NewQuery(query string) string {
	return fmt.Sprintf("WITH request_id AS (SELECT '%s') %s", storeTx.requestID.String(), query)
}

// Fetches a user from the database
// If no user is found it returns the ErrNoRows error
func (storeTx *AuthStoreTx) GetUser(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	var fetchedID []byte

	row := storeTx.tx.QueryRow(ctx, storeTx.NewQuery("SELECT * FROM users WHERE id = $1"), userID)
	err := row.Scan(&fetchedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return fetchedID, nil
}

// Creates a user with a tag, updates the tag if the user exists
// Returns an error if SQL query fails to execute in authstorage DB
func (storeTx *AuthStoreTx) UpsertUser(ctx context.Context, userID uuid.UUID) error {
	_, err := storeTx.tx.Exec(ctx, storeTx.NewQuery("UPSERT INTO users (id) VALUES ($1)"), userID)
	return err
}

// GetAccessObject fetches data, tag of an Access Object with given Object ID
func (storeTx *AuthStoreTx) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	var data, tag []byte

	row := storeTx.tx.QueryRow(ctx, storeTx.NewQuery("SELECT data, tag FROM access_objects WHERE id = $1"), objectID)
	err := row.Scan(&data, &tag)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNoRows
	}
	if err != nil {
		return nil, nil, err
	}

	return data, tag, err
}

// InsertAcccessObject inserts an Access Object (Object ID, data, tag)
func (storeTx *AuthStoreTx) InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	_, err := storeTx.tx.Exec(ctx, storeTx.NewQuery("INSERT INTO access_objects (id, data, tag) VALUES ($1, $2, $3)"), objectID, data, tag)
	return err
}

// UpdateAccessObject updates an Access Object with Object ID and sets data, tag
func (storeTx *AuthStoreTx) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	_, err := storeTx.tx.Exec(ctx, storeTx.NewQuery("UPDATE access_objects SET data = $1, tag = $2 WHERE id = $3"), data, tag, objectID)
	return err
}
