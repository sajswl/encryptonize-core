package config

import (
	"context"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	log "encryption-service/logger"
)

type Config struct {
	KEK               []byte
	ASK               []byte
	TEK               []byte
	AuthStorageURL    string
	ObjectStorageURL  string
	ObjectStorageID   string
	ObjectStorageKey  string
	ObjectStorageCert []byte
}

const stopSign = `
            uuuuuuuuuuuuuuuuuuuu
          u* uuuuuuuuuuuuuuuuuu *u
        u* u$$$$$$$$$$$$$$$$$$$$u *u
      u* u$$$$$$$$$$$$$$$$$$$$$$$$u *u
    u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
  u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
$ $$$* ... *$...  ...$* ... *$$$  ... *$$$ $
$ $$$u **$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $
$ $$$$$$uu *$$$$  $$$  $$$$$  $$  *** u$$$ $
$ $$$**$$$  $$$$  $$$u *$$$* u$$  $$$$$$$$ $
$ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
*u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
  *u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
    *u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
      *u *$$$$$$$$$$$$$$$$$$$$$$$$* u*
        *u *$$$$$$$$$$$$$$$$$$$$* u*
          *u ****************** u*
            ********************

          RUNNING IN INSECURE MODE`

func ParseConfig() (*Config, error) {
	config := &Config{}

	var KEKHex string
	var ASKHex string
	var TEKHex string
	var ObjectStorageCertFromEnv string
	a := []struct {
		EnvName      string
		ConfigTarget *string
		Optional     bool
	}{
		{"KEK", &KEKHex, false},
		{"ASK", &ASKHex, false},
		{"TEK", &TEKHex, false},
		{"AUTH_STORAGE_URL", &config.AuthStorageURL, false},
		{"OBJECT_STORAGE_URL", &config.ObjectStorageURL, false},
		{"OBJECT_STORAGE_ID", &config.ObjectStorageID, false},
		{"OBJECT_STORAGE_KEY", &config.ObjectStorageKey, false},
		{"OBJECT_STORAGE_CERT", &ObjectStorageCertFromEnv, false},
	}

	for _, c := range a {
		v, ok := os.LookupEnv(c.EnvName)
		if !c.Optional && !ok {
			return nil, errors.New(c.EnvName + " env missing")
		}
		*c.ConfigTarget = v
	}

	KEK, err := hex.DecodeString(KEKHex)
	if err != nil {
		return nil, errors.New("KEK env couldn't be parsed (decode hex)")
	}
	if len(KEK) != 32 {
		return nil, errors.New("KEK must be 32 bytes (64 hex digits) long")
	}
	config.KEK = KEK

	ASK, err := hex.DecodeString(ASKHex)
	if err != nil {
		return nil, errors.New("ASK env couldn't be parsed (decode hex)")
	}
	if len(ASK) != 32 {
		return nil, errors.New("ASK must be 32 bytes (64 hex digits) long")
	}
	config.ASK = ASK

	TEK, err := hex.DecodeString(TEKHex)
	if err != nil {
		return nil, errors.New("TEK env couldn't be parsed (decode hex)")
	}
	if len(TEK) != 32 {
		return nil, errors.New("TEK must be 32 bytes (64 hex digits) long")
	}
	config.TEK = TEK

	// Read object storage ID, key and certificate from file if env var not specified
	if config.ObjectStorageID == "" {
		objectStorageID, err := ioutil.ReadFile("data/object_storage_id")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_ID from file")
		}
		objectStorageKey, err := ioutil.ReadFile("data/object_storage_key")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_KEY from file")
		}
		config.ObjectStorageID = strings.TrimSpace(string(objectStorageID))
		config.ObjectStorageKey = strings.TrimSpace(string(objectStorageKey))
	}
	if ObjectStorageCertFromEnv == "" {
		objectStorageCert, err := ioutil.ReadFile("data/object_storage.crt")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_CERT from file")
		}
		config.ObjectStorageCert = objectStorageCert
	} else {
		config.ObjectStorageCert = []byte(ObjectStorageCertFromEnv)
	}

	CheckInsecure(config)

	return config, nil
}

// Prevents an accidental deployment with testing parameters
func CheckInsecure(config *Config) {
	ctx := context.TODO()

	if os.Getenv("ENCRYPTION_SERVICE_INSECURE") == "1" {
		for _, line := range strings.Split(stopSign, "\n") {
			log.Warn(ctx, line)
		}
	} else {
		if hex.EncodeToString(config.KEK) == "0000000000000000000000000000000000000000000000000000000000000000" {
			log.Fatal(ctx, "Test KEK used outside of INSECURE testing mode", errors.New(""))
		}
		if hex.EncodeToString(config.ASK) == "0000000000000000000000000000000000000000000000000000000000000001" {
			log.Fatal(ctx, "Test ASK used outside of INSECURE testing mode", errors.New(""))
		}
		if hex.EncodeToString(config.TEK) == "0000000000000000000000000000000000000000000000000000000000000002" {
			log.Fatal(ctx, "Test TEK used outside of INSECURE testing mode", errors.New(""))
		}
	}
}
