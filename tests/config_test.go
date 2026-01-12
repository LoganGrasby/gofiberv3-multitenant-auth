package tests

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func TestDefaultConfig(t *testing.T) {
	cfg := auth.DefaultConfig()

	assertEqual(t, cfg.DatabaseDir, "./data/tenants")
	assertEqual(t, cfg.JWTAccessExpiration, 15*time.Minute)
	assertEqual(t, cfg.JWTRefreshExpiration, 7*24*time.Hour)
	assertEqual(t, cfg.APIKeyLength, 32)
	assertEqual(t, cfg.APIKeyPrefix, "sk_")
	assertEqual(t, cfg.BcryptCost, 12)
	assertTrue(t, cfg.CookieSecure, "CookieSecure should be true")
	assertTrue(t, cfg.CookieHTTPOnly, "CookieHTTPOnly should be true")
	assertEqual(t, cfg.CookieSameSite, "Lax")
	assertTrue(t, cfg.AllowTenantCreation, "AllowTenantCreation should be true")
	assertNotNil(t, cfg.TenantExtractor, "TenantExtractor should not be nil")
}

func TestConfigValidate_Success(t *testing.T) {
	cfg := setupTestConfig(t)
	err := cfg.Validate()
	assertNoError(t, err)
}

func TestConfigValidate_EmptyDatabaseDir(t *testing.T) {
	cfg := setupTestConfig(t)
	cfg.DatabaseDir = ""

	err := cfg.Validate()

	if err == nil {
		t.Fatal("expected error for empty DatabaseDir")
	}
	if _, ok := err.(auth.ErrInvalidConfig); !ok {
		t.Errorf("expected auth.ErrInvalidConfig, got %T", err)
	}
}

func TestConfigValidate_NilTenantExtractor(t *testing.T) {
	cfg := setupTestConfig(t)
	cfg.TenantExtractor = extractors.Extractor{} // Empty extractor with nil Extract

	err := cfg.Validate()

	if err == nil {
		t.Fatal("expected error for nil TenantExtractor")
	}
	if e, ok := err.(auth.ErrInvalidConfig); !ok {
		t.Errorf("expected auth.ErrInvalidConfig, got %T", err)
	} else {
		assertEqual(t, e.Field, "TenantExtractor")
	}
}

func TestConfigValidate_EmptyJWTSecret(t *testing.T) {
	cfg := setupTestConfig(t)
	cfg.JWTSecret = nil

	err := cfg.Validate()

	if err == nil {
		t.Fatal("expected error for empty JWTSecret")
	}
	if e, ok := err.(auth.ErrInvalidConfig); !ok {
		t.Errorf("expected auth.ErrInvalidConfig, got %T", err)
	} else {
		assertEqual(t, e.Field, "JWTSecret")
	}
}

func TestConfigValidate_ShortJWTSecret(t *testing.T) {
	cfg := setupTestConfig(t)
	cfg.JWTSecret = []byte("short") // Less than 32 bytes

	err := cfg.Validate()

	if err == nil {
		t.Fatal("expected error for short JWTSecret")
	}
	if e, ok := err.(auth.ErrInvalidConfig); !ok {
		t.Errorf("expected auth.ErrInvalidConfig, got %T", err)
	} else {
		assertEqual(t, e.Field, "JWTSecret")
	}
}

func TestConfigValidate_DefaultsApplied(t *testing.T) {
	cfg := auth.Config{
		DatabaseDir:          setupTestDir(t),
		TenantExtractor:      extractors.FromCustom("test", func(c fiber.Ctx) (string, error) { return "test", nil }),
		JWTSecret:            testSecret,
		JWTAccessExpiration:  0, // Should get default
		JWTRefreshExpiration: 0, // Should get default
		APIKeyLength:         0, // Should get default
		BcryptCost:           0, // Should get default
	}

	err := cfg.Validate()
	assertNoError(t, err)

	// Verify defaults were applied
	assertEqual(t, cfg.JWTAccessExpiration, 15*time.Minute)
	assertEqual(t, cfg.JWTRefreshExpiration, 7*24*time.Hour)
	assertEqual(t, cfg.APIKeyLength, 32)
	assertEqual(t, cfg.BcryptCost, 12)
}

func TestConfigValidate_NegativeValuesGetDefaults(t *testing.T) {
	cfg := auth.Config{
		DatabaseDir:          setupTestDir(t),
		TenantExtractor:      extractors.FromCustom("test", func(c fiber.Ctx) (string, error) { return "test", nil }),
		JWTSecret:            testSecret,
		JWTAccessExpiration:  -1 * time.Minute,
		JWTRefreshExpiration: -1 * time.Hour,
		APIKeyLength:         -1,
		BcryptCost:           -1,
	}

	err := cfg.Validate()
	assertNoError(t, err)

	// Verify defaults were applied for negative values
	assertEqual(t, cfg.JWTAccessExpiration, 15*time.Minute)
	assertEqual(t, cfg.JWTRefreshExpiration, 7*24*time.Hour)
	assertEqual(t, cfg.APIKeyLength, 32)
	assertEqual(t, cfg.BcryptCost, 12)
}
