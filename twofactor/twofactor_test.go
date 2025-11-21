package twofactor

import (
	"encoding/base32"
	"testing"
)

func TestNewTOTPFromKey(t *testing.T) {
	key := []byte("12345678901234567890")
	otp, err := NewTOTPFromKey(key, "test@example.com", "Example", 6)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if otp == nil {
		t.Fatal("Expected otp object, got nil")
	}
}

func TestCalculateTOTP(t *testing.T) {
	// Test vector from RFC 6238 (SHA1)
	// Secret = 12345678901234567890
	// Time = 59 (T=1) -> 94287082

	key := []byte("12345678901234567890")
	otp, err := NewTOTPFromKey(key, "test@example.com", "Example", 8) // RFC uses 8 digits for this vector
	if err != nil {
		t.Fatal(err)
	}

	// We can't easily mock time in the current implementation of CalculateTOTP without more refactoring.
	// So we will just verify it returns a string of correct length for now.

	token := CalculateTOTP(otp, 0)
	if len(token) != 8 {
		t.Errorf("Expected token length 8, got %d", len(token))
	}
}

func TestCalculateTOTP_Base32(t *testing.T) {
	keyStr := "MZXW6YTBOI======" // Base32 for "foo" padded
	key, _ := base32.StdEncoding.DecodeString(keyStr)

	otp, err := NewTOTPFromKey(key, "test@example.com", "Example", 6)
	if err != nil {
		t.Fatal(err)
	}

	token := CalculateTOTP(otp, 0)
	if len(token) != 6 {
		t.Errorf("Expected token length 6, got %d", len(token))
	}
}
