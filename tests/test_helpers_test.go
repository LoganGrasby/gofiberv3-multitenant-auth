package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testSecret is a consistent secret used across all tests.
var testSecret = []byte("test-secret-key-that-is-at-least-32-bytes-long")

// testTenantID is a consistent tenant ID used across tests.
const testTenantID = "test-tenant"

// testUserEmail and testUserPassword are consistent credentials for tests.
const (
	testUserEmail    = "test@example.com"
	testUserPassword = "password123"
)

// setupTestDir creates a temporary directory for test databases.
func setupTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gofiber-auth-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	return dir
}

// setupTestConfig creates a test configuration.
func setupTestConfig(t *testing.T) auth.Config {
	t.Helper()
	return auth.Config{
		DatabaseDir:          setupTestDir(t),
		TenantExtractor:      extractors.FromCustom("static", func(c fiber.Ctx) (string, error) { return testTenantID, nil }),
		JWTSecret:            testSecret,
		JWTAccessExpiration:  15 * time.Minute,
		JWTRefreshExpiration: 7 * 24 * time.Hour,
		APIKeyLength:         32,
		APIKeyPrefix:         "sk_test_",
		BcryptCost:           4, // Low cost for faster tests
		CookieSecure:         false,
		CookieHTTPOnly:       true,
		CookieSameSite:       "Lax",
		AllowTenantCreation:  true,
	}
}

// setupTestService creates a test auth service with an in-memory configuration.
func setupTestService(t *testing.T) *auth.Service[*auth.User] {
	t.Helper()
	config := setupTestConfig(t)
	svc, err := auth.New(config)
	if err != nil {
		t.Fatalf("failed to create test service: %v", err)
	}
	t.Cleanup(func() {
		svc.Close()
	})
	return svc
}

// setupTestDB creates an isolated in-memory SQLite database for testing.
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	// Run migrations
	if err := db.AutoMigrate(auth.AllModels()...); err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}

	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	})

	return db
}

// setupTestServiceWithDB creates a test service and returns a database for a specific tenant.
func setupTestServiceWithDB(t *testing.T) (*auth.Service[*auth.User], *gorm.DB) {
	t.Helper()
	svc := setupTestService(t)
	db, err := svc.DatabaseManager().GetDB(context.Background(), testTenantID)
	if err != nil {
		t.Fatalf("failed to get test database: %v", err)
	}
	return svc, db
}

// createTestUser creates a user with known credentials in the database.
func createTestUser(t *testing.T, db *gorm.DB, svc *auth.Service[*auth.User]) *auth.User {
	t.Helper()
	user, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    testUserEmail,
		Password: testUserPassword,
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

// createTestUserWithEmail creates a user with a specific email.
func createTestUserWithEmail(t *testing.T, db *gorm.DB, svc *auth.Service[*auth.User], email string) *auth.User {
	t.Helper()
	user, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    email,
		Password: testUserPassword,
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

// createTestAPIKey creates an API key for a user.
func createTestAPIKey(t *testing.T, db *gorm.DB, svc *auth.Service[*auth.User], userID uint, name string) (*auth.APIKey, string) {
	t.Helper()
	result, err := svc.CreateAPIKey(context.Background(), db, userID, auth.CreateAPIKeyInput{
		Name:        name,
		Scopes:      []string{"read", "write"},
		Description: "Test API Key",
	})
	if err != nil {
		t.Fatalf("failed to create test API key: %v", err)
	}
	return result.APIKey, result.RawKey
}

// createExpiredAPIKey creates an API key that has already expired.
func createExpiredAPIKey(t *testing.T, db *gorm.DB, svc *auth.Service[*auth.User], userID uint) (*auth.APIKey, string) {
	t.Helper()
	expiry := time.Now().Add(-time.Hour) // Expired 1 hour ago
	result, err := svc.CreateAPIKey(context.Background(), db, userID, auth.CreateAPIKeyInput{
		Name:      "Expired Key",
		ExpiresAt: &expiry,
	})
	if err != nil {
		t.Fatalf("failed to create expired API key: %v", err)
	}
	return result.APIKey, result.RawKey
}

// generateTestJWT generates a valid JWT for testing.
func generateTestJWT(t *testing.T, svc *auth.Service[*auth.User], userID uint, tenantID string) string {
	t.Helper()
	now := time.Now()
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   fmt.Sprintf("%d", userID),
		},
		UserID:   userID,
		TenantID: tenantID,
		Email:    testUserEmail,
		Role:     "user",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(svc.Config().JWTSecret)
	if err != nil {
		t.Fatalf("failed to generate test JWT: %v", err)
	}
	return tokenString
}

// generateExpiredJWT generates an expired JWT for testing.
func generateExpiredJWT(t *testing.T, svc *auth.Service[*auth.User], userID uint, tenantID string) string {
	t.Helper()
	now := time.Now()
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			Subject:   fmt.Sprintf("%d", userID),
		},
		UserID:   userID,
		TenantID: tenantID,
		Email:    testUserEmail,
		Role:     "user",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(svc.Config().JWTSecret)
	if err != nil {
		t.Fatalf("failed to generate expired JWT: %v", err)
	}
	return tokenString
}

// setupTestApp creates a Fiber app with common middleware for testing.
func setupTestApp(t *testing.T, svc *auth.Service[*auth.User]) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})
	return app
}

// setupTestAppWithTenant creates a Fiber app with tenant middleware.
func setupTestAppWithTenant(t *testing.T, svc *auth.Service[*auth.User]) *fiber.App {
	t.Helper()
	app := setupTestApp(t, svc)
	app.Use(svc.TenantMiddleware())
	return app
}

// setupTestAppWithAuth creates a Fiber app with tenant and auth middleware.
func setupTestAppWithAuth(t *testing.T, svc *auth.Service[*auth.User]) *fiber.App {
	t.Helper()
	app := setupTestAppWithTenant(t, svc)
	app.Use(svc.AuthMiddleware())
	return app
}

// TestDatabaseFile is a helper to create a file-based SQLite database for tests
// that need to test file operations.
func setupTestDBFile(t *testing.T, dir, tenantID string) string {
	t.Helper()
	dbPath := filepath.Join(dir, tenantID+".db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to create test database file: %v", err)
	}
	if err := db.AutoMigrate(auth.AllModels()...); err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}
	sqlDB, _ := db.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}
	return dbPath
}

// assertError checks that an error matches the expected error.
func assertError(t *testing.T, got, want error) {
	t.Helper()
	if got == nil && want == nil {
		return
	}
	if got == nil {
		t.Errorf("expected error %v, got nil", want)
		return
	}
	if want == nil {
		t.Errorf("unexpected error: %v", got)
		return
	}
	if got.Error() != want.Error() {
		t.Errorf("error mismatch:\n  got:  %v\n  want: %v", got, want)
	}
}

// assertNoError checks that no error occurred.
func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// assertEqual checks that two values are equal.
func assertEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("value mismatch:\n  got:  %v\n  want: %v", got, want)
	}
}

// assertNotEqual checks that two values are not equal.
func assertNotEqual[T comparable](t *testing.T, got, notWant T) {
	t.Helper()
	if got == notWant {
		t.Errorf("values should not be equal: %v", got)
	}
}

// assertTrue checks that a value is true.
func assertTrue(t *testing.T, got bool, msg string) {
	t.Helper()
	if !got {
		t.Errorf("expected true: %s", msg)
	}
}

// assertFalse checks that a value is false.
func assertFalse(t *testing.T, got bool, msg string) {
	t.Helper()
	if got {
		t.Errorf("expected false: %s", msg)
	}
}

// assertNil checks that a value is nil.
func assertNil(t *testing.T, got interface{}, msg string) {
	t.Helper()
	if got != nil {
		t.Errorf("expected nil: %s, got %v", msg, got)
	}
}

// assertNotNil checks that a value is not nil.
func assertNotNil(t *testing.T, got interface{}, msg string) {
	t.Helper()
	if got == nil {
		t.Errorf("expected not nil: %s", msg)
	}
}
