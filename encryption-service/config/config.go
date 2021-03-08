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

package config

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"

	log "encryption-service/logger"
)

type Config struct {
	Keys          Keys          `koanf:"keys"`
	AuthStorage   AuthStorage   `koanf:"authstorage"`
	ObjectStorage ObjectStorage `koanf:"objectstorage"`
}

type Keys struct {
	KEK []byte `koanf:"kek"`
	ASK []byte `koanf:"ask"`
	TEK []byte `koanf:"tek"`
}

type AuthStorage struct {
	URL string `koanf:"url"`
}

type ObjectStorage struct {
	URL  string `koanf:"url"`
	ID   string `koanf:"id"`
	Key  string `koanf:"key"`
	Cert []byte `koanf:"cert"`
}

func ParseConfig() (*Config, error) {
	config := Config{}
	err := LoadConfig(&config)
	if err != nil {
		return nil, err
	}
	if err := config.ParseConfig(); err != nil {
		return nil, err
	}
	return &config, nil
}

func LoadConfig(config interface{}) error {
	var k = koanf.New(".")

	// Load configuration file
	configFile := "config.toml"
	path, set := os.LookupEnv("ECTNZ_CONFIGFILE")
	if set {
		configFile = path
	}

	var parser koanf.Parser
	switch filepath.Ext(configFile) {
	case ".toml":
		parser = toml.Parser()
	case ".yaml":
		parser = yaml.Parser()
	case ".json":
		parser = json.Parser()
	default:
		log.Warnf(context.TODO(), "Unknown config file extension, defaulting to TOML")
		parser = toml.Parser()
	}

	log.Infof(context.TODO(), "Loading config from %v", configFile)
	err := k.Load(file.Provider(configFile), parser)
	if err != nil {
		log.Warnf(context.TODO(), "Failed to read config file, skipping: %v", err)
	}

	// Merge with environment variables
	err = k.Load(env.Provider("ECTNZ_", ".", func(s string) string {
		return strings.Replace(strings.ToLower(strings.TrimPrefix(s, "ECTNZ_")), "_", ".", -1)
	}), nil)
	if err != nil {
		return err
	}

	// Read configuration into interface
	if err := k.Unmarshal("", &config); err != nil {
		return err
	}

	return nil
}

func (c *Config) ParseConfig() error {
	// Process subconfigurations
	if err := c.Keys.ParseConfig(); err != nil {
		return err
	}
	c.Keys.CheckInsecure()

	if err := c.ObjectStorage.ParseConfig(); err != nil {
		return err
	}

	return nil
}

// Converts keys as hex string values to bytes
func (k *Keys) ParseConfig() error {
	var err error
	k.KEK, err = hex.DecodeString(string(k.KEK))
	if err != nil {
		return errors.New("KEK couldn't be parsed (decode hex)")
	}
	if len(k.KEK) != 32 {
		return errors.New("KEK must be 32 bytes (64 hex digits) long")
	}

	k.ASK, err = hex.DecodeString(string(k.ASK))
	if err != nil {
		return errors.New("ASK couldn't be parsed (decode hex)")
	}
	if len(k.ASK) != 32 {
		return errors.New("ASK must be 32 bytes (64 hex digits) long")
	}

	k.TEK, err = hex.DecodeString(string(k.TEK))
	if err != nil {
		return errors.New("TEK couldn't be parsed (decode hex)")
	}
	if len(k.TEK) != 32 {
		return errors.New("TEK must be 32 bytes (64 hex digits) long")
	}

	return nil
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

// Prevents an accidental deployment with testing parameters
func (k *Keys) CheckInsecure() {
	ctx := context.TODO()

	if os.Getenv("ECTNZ_SERVICE_INSECURE") == "1" {
		for _, line := range strings.Split(stopSign, "\n") {
			log.Warn(ctx, line)
		}
	} else {
		if hex.EncodeToString(k.KEK) == "0000000000000000000000000000000000000000000000000000000000000000" {
			log.Fatal(ctx, errors.New(""), "Test KEK used outside of INSECURE testing mode")
		}
		if hex.EncodeToString(k.ASK) == "0000000000000000000000000000000000000000000000000000000000000001" {
			log.Fatal(ctx, errors.New(""), "Test ASK used outside of INSECURE testing mode")
		}
		if hex.EncodeToString(k.TEK) == "0000000000000000000000000000000000000000000000000000000000000002" {
			log.Fatal(ctx, errors.New(""), "Test TEK used outside of INSECURE testing mode")
		}
	}
}

// Reads object storage ID, key and certificate from file if not specified in the config
func (o *ObjectStorage) ParseConfig() error {
	if o.ID == "" {
		id, err := os.ReadFile("data/object_storage_id")
		if err != nil {
			return errors.New("could not read OBJECT_STORAGE_ID from file")
		}
		key, err := os.ReadFile("data/object_storage_key")
		if err != nil {
			return errors.New("could not read OBJECT_STORAGE_KEY from file")
		}
		o.ID = strings.TrimSpace(string(id))
		o.Key = strings.TrimSpace(string(key))
	}
	if len(o.Cert) == 0 {
		cert, err := os.ReadFile("data/object_storage.crt")
		if err != nil {
			return errors.New("could not read OBJECT_STORAGE_CERT from file")
		}
		o.Cert = cert
	}

	return nil
}
