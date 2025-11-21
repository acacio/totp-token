package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/acacio/totp-token/secrets"
	"google.golang.org/protobuf/encoding/prototext"
)

func TestLoadConfig_Flags(t *testing.T) {
	key := "MZXW6YTBOI======"
	loadedKey, err := loadConfig(key, "", "")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if loadedKey != key {
		t.Errorf("Expected key %s, got %s", key, loadedKey)
	}
}

func TestLoadConfig_File(t *testing.T) {
	// Create a temp directory for home
	tmpDir, err := os.MkdirTemp("", "totp_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy .totp-keys file
	totps := &secrets.TOTPSecrets{
		Secrets: []*secrets.Secret{
			{
				Domain: "example.com",
				Key:    "MZXW6YTBOI======",
			},
		},
	}
	data, err := prototext.Marshal(totps)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, ".totp-keys"), data, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Test loading from file
	loadedKey, err := loadConfig("", "example.com", tmpDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if loadedKey != "MZXW6YTBOI======" {
		t.Errorf("Expected key MZXW6YTBOI======, got %s", loadedKey)
	}
}

func TestLoadConfig_Error(t *testing.T) {
	_, err := loadConfig("", "", "")
	if err == nil {
		t.Error("Expected error when no flags provided, got nil")
	}
}
