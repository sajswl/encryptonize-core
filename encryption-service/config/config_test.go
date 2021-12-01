package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var testConfigTOML = `
[keys]
kek = "0101010101010101010101010101010101010101010101010101010101010101"
aek = "0202020202020202020202020202020202020202020202020202020202020202"
tek = "0303030303030303030303030303030303030303030303030303030303030303"
uek = "0404040404040404040404040404040404040404040404040404040404040404"
gek = "0505050505050505050505050505050505050505050505050505050505050505"

[authstorage]
username = "authstorage.username"
host = "authstorage.host"
port = "authstorage.port"
database = "authstorage.database"
sslmode = "authstorage.sslmode"
sslrootcert = "authstorage.sslrootcert"
sslcert = "authstorage.sslcert"
sslkey = "authstorage.sslkey"

[objectstorage]
url = "objectstorage.url"
id = "objectstorage.id"
key = "objectstorage.key"
certpath = "objectstorage.certpath"
`

var testConfigYAML = `
keys:
  kek: "0101010101010101010101010101010101010101010101010101010101010101"
  aek: "0202020202020202020202020202020202020202020202020202020202020202"
  tek: "0303030303030303030303030303030303030303030303030303030303030303"
  uek: "0404040404040404040404040404040404040404040404040404040404040404"
  gek: "0505050505050505050505050505050505050505050505050505050505050505"

authstorage:
  username: "authstorage.username"
  host: "authstorage.host"
  port: "authstorage.port"
  database: "authstorage.database"
  sslmode: "authstorage.sslmode"
  sslrootcert: "authstorage.sslrootcert"
  sslcert: "authstorage.sslcert"
  sslkey: "authstorage.sslkey"

objectstorage:
  url: "objectstorage.url"
  id: "objectstorage.id"
  key: "objectstorage.key"
  certpath: "objectstorage.certpath"
`

var testConfigJSON = `
{
	"keys": {
		"kek": "0101010101010101010101010101010101010101010101010101010101010101",
		"aek": "0202020202020202020202020202020202020202020202020202020202020202",
		"tek": "0303030303030303030303030303030303030303030303030303030303030303",
		"uek": "0404040404040404040404040404040404040404040404040404040404040404",
		"gek": "0505050505050505050505050505050505050505050505050505050505050505"
	},
	"authstorage": {
		"username": "authstorage.username",
		"host": "authstorage.host",
		"port": "authstorage.port",
		"database": "authstorage.database",
		"sslmode": "authstorage.sslmode",
		"sslrootcert": "authstorage.sslrootcert",
		"sslcert": "authstorage.sslcert",
		"sslkey": "authstorage.sslkey"
	},
	"objectstorage": {
		"url": "objectstorage.url",
		"id": "objectstorage.id",
		"key": "objectstorage.key",
		"certpath": "objectstorage.certpath"
	}
}
`

var testConfig = Config{
	Keys: Keys{
		KEK: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		AEK: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		TEK: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		UEK: []byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
		GEK: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
	},
	AuthStorage: AuthStorage{
		Username:    "authstorage.username",
		Host:        "authstorage.host",
		Port:        "authstorage.port",
		Database:    "authstorage.database",
		SSLMode:     "authstorage.sslmode",
		SSLRootCert: "authstorage.sslrootcert",
		SSLCert:     "authstorage.sslcert",
		SSLKey:      "authstorage.sslkey",
	},
	ObjectStorage: ObjectStorage{
		URL:      "objectstorage.url",
		ID:       "objectstorage.id",
		Key:      "objectstorage.key",
		CertPath: "objectstorage.certpath",
	},
}

func TestReadTOML(t *testing.T) {
	tmpdir := t.TempDir()
	configPath := filepath.Join(tmpdir, "config.toml")
	if err := os.WriteFile(configPath, []byte(testConfigTOML), 0444); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	if err := os.Setenv("ECTNZ_CONFIGFILE", configPath); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	parsedConfig, err := ParseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !reflect.DeepEqual(testConfig, *parsedConfig) {
		t.Fatalf("%v != %v", testConfig, parsedConfig)
	}
}

func TestReadYAML(t *testing.T) {
	tmpdir := t.TempDir()
	configPath := filepath.Join(tmpdir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0444); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	if err := os.Setenv("ECTNZ_CONFIGFILE", configPath); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	parsedConfig, err := ParseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !reflect.DeepEqual(testConfig, *parsedConfig) {
		t.Fatalf("%v != %v", testConfig, parsedConfig)
	}
}

func TestReadJSON(t *testing.T) {
	tmpdir := t.TempDir()
	configPath := filepath.Join(tmpdir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfigJSON), 0444); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	if err := os.Setenv("ECTNZ_CONFIGFILE", configPath); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	parsedConfig, err := ParseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !reflect.DeepEqual(testConfig, *parsedConfig) {
		t.Fatalf("%v != %v", testConfig, parsedConfig)
	}
}

func TestReadUnknownExtension(t *testing.T) {
	tmpdir := t.TempDir()
	configPath := filepath.Join(tmpdir, "config.foo")
	if err := os.WriteFile(configPath, []byte(testConfigTOML), 0444); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	if err := os.Setenv("ECTNZ_CONFIGFILE", configPath); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	parsedConfig, err := ParseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if !reflect.DeepEqual(testConfig, *parsedConfig) {
		t.Fatalf("%v != %v", testConfig, parsedConfig)
	}
}

func TestReadEnv(t *testing.T) {
	tmpdir := t.TempDir()
	configPath := filepath.Join(tmpdir, "config.toml")
	if err := os.WriteFile(configPath, []byte(testConfigTOML), 0444); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	if err := os.Setenv("ECTNZ_CONFIGFILE", configPath); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}

	// Overwrite with environment variables
	if err := os.Setenv("ECTNZ_OBJECTSTORAGE_URL", "another object url"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}

	if err := os.Setenv("ECTNZ_AUTHSTORAGE_HOST", "another auth host"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}

	parsedConfig, err := ParseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if reflect.DeepEqual(testConfig, *parsedConfig) {
		t.Fatalf("%v == %v", testConfig, parsedConfig)
	}

	testConfig.ObjectStorage.URL = "another object url"
	testConfig.AuthStorage.Host = "another auth host"

	if !reflect.DeepEqual(testConfig, *parsedConfig) {
		t.Fatalf("%v != %v", testConfig, parsedConfig)
	}
}

func TestParseKeys(t *testing.T) {
	testKeys := Keys{
		KEK: []byte("0101010101010101010101010101010101010101010101010101010101010101"),
		AEK: []byte("0202020202020202020202020202020202020202020202020202020202020202"),
		TEK: []byte("0303030303030303030303030303030303030303030303030303030303030303"),
		UEK: []byte("0404040404040404040404040404040404040404040404040404040404040404"),
		GEK: []byte("0505050505050505050505050505050505050505050505050505050505050505"),
	}
	keys := testKeys

	// Test wrong format
	keys.KEK = []byte("totally not hex")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (KEK)")
	}
	keys = testKeys

	keys.AEK = []byte("totally not hex")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (AEK)")
	}
	keys = testKeys

	keys.TEK = []byte("totally not hex")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (TEK)")
	}
	keys = testKeys

	keys.UEK = []byte("totally not hex")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (UEK)")
	}
	keys = testKeys

	keys.GEK = []byte("totally not hex")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (GEK)")
	}
	keys = testKeys

	// Test wrong length
	keys.KEK = []byte("deadbeef")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (KEK)")
	}
	keys = testKeys

	keys.AEK = []byte("deadbeef")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (AEK)")
	}
	keys = testKeys

	keys.TEK = []byte("deadbeef")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (TEK)")
	}
	keys = testKeys

	keys.UEK = []byte("deadbeef")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (UEK)")
	}
	keys = testKeys

	keys.GEK = []byte("deadbeef")
	if err := keys.ParseConfig(); err == nil {
		t.Error("Expected ParseConfig to fail (GEK)")
	}
	keys = testKeys
}
