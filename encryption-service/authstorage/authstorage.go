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

	"encryption-service/contextkeys"
	"github.com/gofrs/uuid"
	"github.com/jackc/pgtype"
	pgtypeuuid "github.com/jackc/pgtype/ext/gofrs-uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	log "github.com/sirupsen/logrus"
	"github.com/sony/gobreaker"
)

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
			log.Infof("Circuitbreaker %s has changed state from %v to %v", name, from, to)
		},
	}

	return gobreaker.NewCircuitBreaker(st)
}

// Abstraction interface mainly used for testing
type AuthStoreInterface interface {
	Rollback(ctx context.Context) error
	Commit(ctx context.Context) error

	// User handling
	GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error)
	UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error

	// Access Object handling
	GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error)
	InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
	UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
}

// ErrNoRows : Return this error when an empty record set is returned for the DB
// e.g. when a users isn't found
var ErrNoRows = errors.New("no rows in result set")
var cb *gobreaker.CircuitBreaker = initCircuitBreaker()

// ConnectDBPool creates a new DB pool for the DB URL (postgresql://...).
// Additionally, it configures the pool to use `gofrs-uuid` for handling UUIDs.
// TODO: configure connection pool (min, max connections etc.)
func ConnectDBPool(ctx context.Context, URL string) (*pgxpool.Pool, error) {
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
	return pool, nil
}

// DBAuthStore encapsulates a DB Tx for the authentication storage
type DBAuthStore struct {
	tx        pgx.Tx
	requestID uuid.UUID
}

// NewDBAuthStore starts a new Transaction (tx) in the pool and instances an DBAuthStore with it
func NewDBAuthStore(ctx context.Context, pool *pgxpool.Pool) (*DBAuthStore, error) {
	// Wrap DB connection in a circuit breaker. By default, it trips to "open" state after 5 consecutive failures.
	tx, err := cb.Execute(func() (interface{}, error) {
		tx, err := pool.Begin(ctx)

		if err != nil {
			return nil, err
		}

		return tx, err
	})

	if err != nil {
		return nil, err
	}

	authStorage := &DBAuthStore{
		tx:        tx.(pgx.Tx),
		requestID: ctx.Value(contextkeys.RequestIDCtxKey).(uuid.UUID),
	}
	return authStorage, nil
}

// Used as a defer function to rollback an unfinished transaction
func (storage *DBAuthStore) Rollback(ctx context.Context) error {
	err := storage.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Commit commits the encapsulated transcation
func (storage *DBAuthStore) Commit(ctx context.Context) error {
	return storage.tx.Commit(ctx)
}

// Enriches the query with request id for tracing to the SQL audit log
func (storage *DBAuthStore) NewQuery(query string) string {
	return fmt.Sprintf("WITH request_id AS (SELECT '%s') %s", storage.requestID.String(), query)
}

// Fetches a tag from the database
// If no user is found it returns the ErrNoRows error
func (storage *DBAuthStore) GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	var storedTag []byte

	row := storage.tx.QueryRow(ctx, storage.NewQuery("SELECT tag FROM users WHERE id = $1"), userID)
	err := row.Scan(&storedTag)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return storedTag, nil
}

// Creates a user with a tag, updates the tag if the user exists
// Returns an error if SQL query fails to execute in authstorage DB
func (storage *DBAuthStore) UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error {
	_, err := storage.tx.Exec(ctx, storage.NewQuery("UPSERT INTO users (id, tag) VALUES ($1, $2)"), userID, tag)
	return err
}

// GetAccessObject fetches data, tag of an Access Object with given Object ID
func (storage *DBAuthStore) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	var data, tag []byte

	row := storage.tx.QueryRow(ctx, storage.NewQuery("SELECT data, tag FROM access_objects WHERE id = $1"), objectID)
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
func (storage *DBAuthStore) InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	_, err := storage.tx.Exec(ctx, storage.NewQuery("INSERT INTO access_objects (id, data, tag) VALUES ($1, $2, $3)"), objectID, data, tag)
	return err
}

// UpdateAccessObject updates an Access Object with Object ID and sets data, tag
func (storage *DBAuthStore) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	_, err := storage.tx.Exec(ctx, storage.NewQuery("UPDATE access_objects SET data = $1, tag = $2 WHERE id = $3"), data, tag, objectID)
	return err
}
