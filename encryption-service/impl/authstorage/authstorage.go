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
package authstorage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgtype"
	pgtypeuuid "github.com/jackc/pgtype/ext/gofrs-uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/sony/gobreaker"

	"encryption-service/common"
	"encryption-service/config"
	"encryption-service/interfaces"
	log "encryption-service/logger"
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
			msg := fmt.Sprintf("Circuitbreaker %s has changed state from %v to %v", name, from, to)
			log.Info(context.TODO(), msg)
		},
	}

	return gobreaker.NewCircuitBreaker(st)
}

var cb *gobreaker.CircuitBreaker = initCircuitBreaker()

// Implementation of the AuthStoreInterface
type AuthStore struct {
	Pool *pgxpool.Pool
}

// Implementation of AuthStoreTxInterface
type AuthStoreTx struct {
	Tx        pgx.Tx
	RequestID uuid.UUID
}

// NewAuthStore creates a new DB pool for the given database configuration.
// Additionally, it configures the pool to use `gofrs-uuid` for handling UUIDs.
// TODO: configure connection pool (min, max connections etc.)
func NewAuthStore(ctx context.Context, config config.AuthStorage) (*AuthStore, error) {
	connectionString := fmt.Sprintf("postgresql://%s@%s:%s/%s?sslmode=%s&sslrootcert=%s&sslcert=%s&sslkey=%s",
		config.Username, config.Host, config.Port, config.Database, config.SSLMode, config.SSLRootCert, config.SSLCert, config.SSLKey)

	pgxConfig, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, err
	}
	if config.Password != "" {
		pgxConfig.ConnConfig.Password = config.Password
	}
	pgxConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		conn.ConnInfo().RegisterDataType(pgtype.DataType{
			Value: &pgtypeuuid.UUID{},
			Name:  "uuid",
			OID:   pgtype.UUIDOID,
		})
		return nil
	}
	pgxConfig.LazyConnect = true                                                 // Don't need to connect immediately
	pgxConfig.ConnConfig.Config.ConnectTimeout = time.Duration(10) * time.Second // If we cannot connect in 10 seconds, then we most likely cannot connect at all

	pool, err := pgxpool.ConnectConfig(ctx, pgxConfig)
	if err != nil {
		return nil, err
	}
	return &AuthStore{Pool: pool}, nil
}

// NewTransaction starts a new Transaction (tx) in the pool and instances an AuthStoreTx with it
func (store *AuthStore) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	// Wrap DB connection in a circuit breaker. By default, it trips to "open" state after 5 consecutive failures.
	tx, err := cb.Execute(func() (interface{}, error) {
		tx, err := store.Pool.Begin(ctx)

		if err != nil {
			return nil, err
		}

		return tx, err
	})

	if err != nil {
		return nil, err
	}

	requestID, ok := ctx.Value(common.RequestIDCtxKey).(uuid.UUID)
	if !ok {
		return nil, errors.New("Could not typecast requestID to uuid.UUID")
	}

	authStorage := &AuthStoreTx{
		Tx:        tx.(pgx.Tx),
		RequestID: requestID,
	}

	return authStorage, nil
}

func (store *AuthStore) Close() {
	store.Pool.Close()
}

// ImportSchema reads a schema file and executes it
func (store *AuthStore) ImportSchema(ctx context.Context, schemaFile string) error {
	log.Info(ctx, "ImportSchema started")
	schemaData, err := os.ReadFile(schemaFile)
	if err != nil {
		return err
	}

	// Wait for DB to be up
	// TODO: this is not ideal
	for i := 0; i < 120; i++ {
		// We don't use ping here, as that would succeed even if the right database has not been created yet.
		_, err = store.Pool.Exec(ctx, string(schemaData))
		if err == nil {
			break
		}

		log.Debugf(ctx, "Auth Storage setup failed (retrying ...) - %v", err)
		time.Sleep(time.Second)
	}

	return err
}

// Used as a defer function to rollback an unfinished transaction
func (storeTx *AuthStoreTx) Rollback(ctx context.Context) error {
	err := storeTx.Tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Commit commits the encapsulated transcation
func (storeTx *AuthStoreTx) Commit(ctx context.Context) error {
	return storeTx.Tx.Commit(ctx)
}

// Enriches the query with request id for tracing to the SQL audit log
func (storeTx *AuthStoreTx) NewQuery(query string) string {
	return fmt.Sprintf("WITH request_id AS (SELECT '%s') %s", storeTx.RequestID.String(), query)
}

// InsertUser inserts a user into the auth store
func (storeTx *AuthStoreTx) InsertUser(ctx context.Context, protected *common.ProtectedUserData) error {
	_, err := storeTx.Tx.Exec(ctx, storeTx.NewQuery("INSERT INTO users (id, data, key) VALUES ($1, $2, $3)"), protected.UserID, protected.UserData, protected.WrappedKey)
	return err
}

// UpdateUser updates an existing user's data
func (storeTx *AuthStoreTx) UpdateUser(ctx context.Context, protected *common.ProtectedUserData) error {
	res, err := storeTx.Tx.Exec(ctx, storeTx.NewQuery("UPDATE users SET data = $1, key = $2 WHERE id = $3 AND deleted_at IS NULL"), protected.UserData, protected.WrappedKey, protected.UserID)
	if err != nil {
		return err
	}
	if res.RowsAffected() < 1 {
		return interfaces.ErrNotFound
	}
	return nil
}

// RemoveUser performs a soft delete by setting a deletion date
func (storeTx *AuthStoreTx) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	res, err := storeTx.Tx.Exec(ctx, storeTx.NewQuery("UPDATE users SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL"), now, userID)
	if err != nil {
		return err
	}
	if res.RowsAffected() < 1 {
		return interfaces.ErrNotFound
	}
	return nil
}

// Gets user's confidential data
func (storeTx *AuthStoreTx) GetUserData(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
	protected := &common.ProtectedUserData{UserID: userID}
	row := storeTx.Tx.QueryRow(ctx, storeTx.NewQuery("SELECT data, key FROM users WHERE id = $1 AND deleted_at IS NULL"), userID)
	err := row.Scan(&protected.UserData, &protected.WrappedKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, interfaces.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return protected, nil
}

// GroupExists checks if a group exists in the auth store
func (storeTx *AuthStoreTx) GroupExists(ctx context.Context, groupID uuid.UUID) (bool, error) {
	var fetchedID []byte

	// TODO: COUNT could be more appropriate
	row := storeTx.Tx.QueryRow(ctx, storeTx.NewQuery("SELECT id FROM groups WHERE id = $1"), groupID)
	err := row.Scan(&fetchedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// InsertGroup inserts a group into the auth store
func (storeTx *AuthStoreTx) InsertGroup(ctx context.Context, protected *common.ProtectedGroupData) error {
	_, err := storeTx.Tx.Exec(ctx, storeTx.NewQuery("INSERT INTO groups (id, data, key) VALUES ($1, $2, $3)"), protected.GroupID, protected.GroupData, protected.WrappedKey)
	return err
}

// Get one or more groups' confidential data
func (storeTx *AuthStoreTx) GetGroupDataBatch(ctx context.Context, groupIDs []uuid.UUID) ([]common.ProtectedGroupData, error) {
	rows, err := storeTx.Tx.Query(ctx, storeTx.NewQuery("SELECT data, key, id FROM groups WHERE id = any($1)"), groupIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	protectedBatch := make([]common.ProtectedGroupData, 0, len(groupIDs))
	for rows.Next() {
		protected := common.ProtectedGroupData{}
		err := rows.Scan(&protected.GroupData, &protected.WrappedKey, &protected.GroupID)
		if err != nil {
			return nil, err
		}

		protectedBatch = append(protectedBatch, protected)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return protectedBatch, nil
}

// GetAccessObject fetches data, tag of an Access Object with given Object ID
func (storeTx *AuthStoreTx) GetAccessObject(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
	protected := &common.ProtectedAccessObject{ObjectID: objectID}

	row := storeTx.Tx.QueryRow(ctx, storeTx.NewQuery("SELECT data, key FROM access_objects WHERE id = $1"), objectID)
	err := row.Scan(&protected.AccessObject, &protected.WrappedKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, interfaces.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return protected, nil
}

// InsertAcccessObject inserts an Access Object (Object ID, data, tag)
func (storeTx *AuthStoreTx) InsertAcccessObject(ctx context.Context, protected *common.ProtectedAccessObject) error {
	_, err := storeTx.Tx.Exec(ctx, storeTx.NewQuery("INSERT INTO access_objects (id, data, key) VALUES ($1, $2, $3)"), protected.ObjectID, protected.AccessObject, protected.WrappedKey)
	return err
}

// UpdateAccessObject updates an Access Object with Object ID and sets data, tag
func (storeTx *AuthStoreTx) UpdateAccessObject(ctx context.Context, protected *common.ProtectedAccessObject) error {
	res, err := storeTx.Tx.Exec(ctx, storeTx.NewQuery("UPDATE access_objects SET data = $1, key = $2 WHERE id = $3"), protected.AccessObject, protected.WrappedKey, protected.ObjectID)
	if err != nil {
		return err
	}
	if res.RowsAffected() < 1 {
		return interfaces.ErrNotFound
	}
	return err
}

func (storeTx *AuthStoreTx) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) error {
	row := storeTx.Tx.QueryRow(ctx, storeTx.NewQuery("SELECT 1 from access_objects WHERE id = $1"), objectID)
	err := row.Scan()
	// No error on OID not found during delete
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	_, err = storeTx.Tx.Exec(ctx, storeTx.NewQuery("DELETE FROM access_objects WHERE id = $1"), objectID)
	return err
}
