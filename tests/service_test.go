package tests

import (
	"context"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func TestNew_Success(t *testing.T) {
	config := setupTestConfig(t)
	svc, err := auth.New(config)
	assertNoError(t, err)
	assertNotNil(t, svc, "service should not be nil")
	defer svc.Close()
}

func TestNew_InvalidConfig(t *testing.T) {
	config := auth.Config{
		// Missing required fields
	}

	_, err := auth.New(config)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	config := auth.Config{
		DatabaseDir:     setupTestDir(t),
		TenantExtractor: extractors.FromCustom("static", func(c fiber.Ctx) (string, error) { return "test", nil }),
		JWTSecret:       testSecret,
		// Leave other fields at zero values
	}

	svc, err := auth.New(config)
	assertNoError(t, err)
	defer svc.Close()

	// Verify defaults were applied
	cfg := svc.Config()
	assertEqual(t, cfg.JWTAccessExpiration, 15*time.Minute)
	assertEqual(t, cfg.JWTRefreshExpiration, 7*24*time.Hour)
	assertEqual(t, cfg.APIKeyLength, 32)
	assertEqual(t, cfg.APIKeyPrefix, "sk_")
	assertEqual(t, cfg.BcryptCost, 12)
}

func TestService_Close(t *testing.T) {
	svc := setupTestService(t)
	err := svc.Close()
	assertNoError(t, err)
}

func TestService_Config(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	cfg := svc.Config()
	assertNotNil(t, cfg.TenantExtractor, "config should have tenant extractor")
}

func TestService_DatabaseManager(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	dm := svc.DatabaseManager()
	assertNotNil(t, dm, "database manager should not be nil")
}

// =============================================================================
// Registration Tests
// =============================================================================

func TestService_Register_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "newuser@example.com",
		Password: "password123",
		Name:     "New User",
	})

	assertNoError(t, err)
	assertNotNil(t, user, "user should not be nil")
	assertEqual(t, user.Email, "newuser@example.com")
	assertEqual(t, user.Name, "New User")
	assertEqual(t, user.Role, "user")
	assertTrue(t, user.Active, "user should be active")
}

func TestService_Register_NormalizesEmail(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	// Test that uppercase emails are normalized to lowercase
	user, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "USER@EXAMPLE.COM",
		Password: "password123",
		Name:     "Test",
	})

	assertNoError(t, err)
	assertEqual(t, user.Email, "user@example.com")
}

func TestService_Register_ValidationError_EmptyEmail(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "",
		Password: "password123",
		Name:     "Test",
	})

	if err == nil {
		t.Error("expected validation error for empty email")
	}
	if _, ok := err.(*auth.ErrValidation); !ok {
		t.Errorf("expected ErrValidation, got %T", err)
	}
}

func TestService_Register_ValidationError_InvalidEmail(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "not-an-email",
		Password: "password123",
		Name:     "Test",
	})

	if err == nil {
		t.Error("expected validation error for invalid email")
	}
}

func TestService_Register_ValidationError_EmptyPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "test@example.com",
		Password: "",
		Name:     "Test",
	})

	if err == nil {
		t.Error("expected validation error for empty password")
	}
}

func TestService_Register_ValidationError_ShortPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "test@example.com",
		Password: "short",
		Name:     "Test",
	})

	if err == nil {
		t.Error("expected validation error for short password")
	}
}

func TestService_Register_DuplicateEmail(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	// Register first user
	_, err := svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "duplicate@example.com",
		Password: "password123",
		Name:     "First User",
	})
	assertNoError(t, err)

	// Try to register with same email
	_, err = svc.Register(context.Background(), db, auth.RegisterInput{
		Email:    "duplicate@example.com",
		Password: "password123",
		Name:     "Second User",
	})

	if err != auth.ErrUserAlreadyExists {
		t.Errorf("expected ErrUserAlreadyExists, got %v", err)
	}
}

// =============================================================================
// Login Tests
// =============================================================================

func TestService_Login_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	// Create user
	createTestUser(t, db, svc)

	// Login
	tokens, user, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	assertNoError(t, err)
	assertNotNil(t, tokens, "tokens should not be nil")
	assertNotNil(t, user, "user should not be nil")
	assertNotEqual(t, tokens.AccessToken, "")
	assertNotEqual(t, tokens.RefreshToken, "")
	assertEqual(t, tokens.TokenType, "Bearer")
}

func TestService_Login_InvalidCredentials_WrongPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	_, _, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: "wrongpassword",
	}, testTenantID)

	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestService_Login_UserNotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, _, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    "nonexistent@example.com",
		Password: "password123",
	}, testTenantID)

	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestService_Login_InactiveUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	// Deactivate user
	db.Model(user).Update("active", false)

	_, _, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

// =============================================================================
// Token Refresh Tests
// =============================================================================

func TestService_RefreshTokens_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	// Login to get tokens
	tokens, _, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)
	assertNoError(t, err)

	// Refresh
	newTokens, err := svc.RefreshTokens(context.Background(), db, tokens.RefreshToken, testTenantID, "", "")
	assertNoError(t, err)
	assertNotNil(t, newTokens, "new tokens should not be nil")
	// New refresh token should always be different (random)
	assertNotEqual(t, newTokens.RefreshToken, tokens.RefreshToken)
	// Access tokens may be the same if generated in the same second (same claims + same iat/exp)
	// The important thing is that we got a valid new token pair
	assertNotEqual(t, newTokens.AccessToken, "")
	assertEqual(t, newTokens.TokenType, "Bearer")
}

func TestService_RefreshTokens_InvalidToken(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.RefreshTokens(context.Background(), db, "invalid-token", testTenantID, "", "")

	if err != auth.ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken, got %v", err)
	}
}

func TestService_RefreshTokens_RevokedToken(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	// Login to get tokens
	tokens, _, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)
	assertNoError(t, err)

	// Use the token once (which revokes it)
	_, err = svc.RefreshTokens(context.Background(), db, tokens.RefreshToken, testTenantID, "", "")
	assertNoError(t, err)

	// Try to use the old token again
	_, err = svc.RefreshTokens(context.Background(), db, tokens.RefreshToken, testTenantID, "", "")
	if err != auth.ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken for revoked token, got %v", err)
	}
}

// =============================================================================
// Logout Tests
// =============================================================================

func TestService_Logout(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	tokens, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	err := svc.Logout(context.Background(), db, tokens.RefreshToken)
	assertNoError(t, err)

	// Token should no longer work
	_, err = svc.RefreshTokens(context.Background(), db, tokens.RefreshToken, testTenantID, "", "")
	if err != auth.ErrInvalidRefreshToken {
		t.Errorf("expected ErrInvalidRefreshToken after logout, got %v", err)
	}
}

func TestService_LogoutAll(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	// Create multiple sessions
	tokens1, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	tokens2, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	// Logout all
	err := svc.LogoutAll(context.Background(), db, user.ID)
	assertNoError(t, err)

	// Both tokens should be invalid
	_, err = svc.RefreshTokens(context.Background(), db, tokens1.RefreshToken, testTenantID, "", "")
	if err != auth.ErrInvalidRefreshToken {
		t.Error("first token should be invalid after LogoutAll")
	}

	_, err = svc.RefreshTokens(context.Background(), db, tokens2.RefreshToken, testTenantID, "", "")
	if err != auth.ErrInvalidRefreshToken {
		t.Error("second token should be invalid after LogoutAll")
	}
}

// =============================================================================
// User Retrieval Tests
// =============================================================================

func TestService_GetUserByID(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	created := createTestUser(t, db, svc)

	user, err := svc.GetUserByID(context.Background(), db, created.ID)
	assertNoError(t, err)
	assertEqual(t, user.Email, testUserEmail)
}

func TestService_GetUserByID_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.GetUserByID(context.Background(), db, 99999)
	if err != auth.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestService_GetUserByEmail(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	user, err := svc.GetUserByEmail(context.Background(), db, testUserEmail)
	assertNoError(t, err)
	assertEqual(t, user.Email, testUserEmail)
}

func TestService_GetUserByEmail_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, err := svc.GetUserByEmail(context.Background(), db, "nonexistent@example.com")
	if err != auth.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

// =============================================================================
// Password Update Tests
// =============================================================================

func TestService_UpdatePassword_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	err := svc.UpdatePassword(context.Background(), db, user.ID, testUserPassword, "newpassword123")
	assertNoError(t, err)

	// Old password should no longer work
	_, _, err = svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)
	if err != auth.ErrInvalidCredentials {
		t.Error("old password should not work after change")
	}

	// New password should work
	_, _, err = svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: "newpassword123",
	}, testTenantID)
	assertNoError(t, err)
}

func TestService_UpdatePassword_WrongOldPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	err := svc.UpdatePassword(context.Background(), db, user.ID, "wrongpassword", "newpassword123")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestService_UpdatePassword_WeakNewPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	err := svc.UpdatePassword(context.Background(), db, user.ID, testUserPassword, "short")
	if err != auth.ErrPasswordTooWeak {
		t.Errorf("expected ErrPasswordTooWeak, got %v", err)
	}
}

func TestService_UpdatePassword_UserNotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	err := svc.UpdatePassword(context.Background(), db, 99999, "old", "newpassword123")
	if err != auth.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

// =============================================================================
// API Key Tests
// =============================================================================

func TestService_CreateAPIKey_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	result, err := svc.CreateAPIKey(context.Background(), db, user.ID, auth.CreateAPIKeyInput{
		Name:        "Test Key",
		Scopes:      []string{"read", "write"},
		Description: "A test API key",
	})

	assertNoError(t, err)
	assertNotNil(t, result, "result should not be nil")
	assertNotEqual(t, result.RawKey, "")
	assertEqual(t, result.APIKey.Name, "Test Key")
	assertTrue(t, len(result.RawKey) > 20, "raw key should be substantial")
}

func TestService_CreateAPIKey_NoName(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	_, err := svc.CreateAPIKey(context.Background(), db, user.ID, auth.CreateAPIKeyInput{
		Name: "",
	})

	if err == nil {
		t.Error("expected validation error for empty name")
	}
}

func TestService_CreateAPIKey_WithExpiry(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	expiry := time.Now().Add(24 * time.Hour)

	result, err := svc.CreateAPIKey(context.Background(), db, user.ID, auth.CreateAPIKeyInput{
		Name:      "Expiring Key",
		ExpiresAt: &expiry,
	})

	assertNoError(t, err)
	assertNotNil(t, result.APIKey.ExpiresAt, "expiry should be set")
}

func TestService_ValidateAPIKey_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Valid Key")

	apiKey, validatedUser, err := svc.ValidateAPIKey(context.Background(), db, rawKey)
	assertNoError(t, err)
	assertNotNil(t, apiKey, "API key should not be nil")
	assertNotNil(t, validatedUser, "user should not be nil")
	assertEqual(t, validatedUser.ID, user.ID)
}

func TestService_ValidateAPIKey_Invalid(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	_, _, err := svc.ValidateAPIKey(context.Background(), db, "invalid-key")
	if err != auth.ErrInvalidAPIKey {
		t.Errorf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestService_ValidateAPIKey_Revoked(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	apiKey, rawKey := createTestAPIKey(t, db, svc, user.ID, "Revoked Key")

	// Revoke the key
	svc.RevokeAPIKey(context.Background(), db, apiKey.ID, user.ID)

	_, _, err := svc.ValidateAPIKey(context.Background(), db, rawKey)
	if err != auth.ErrAPIKeyRevoked {
		t.Errorf("expected ErrAPIKeyRevoked, got %v", err)
	}
}

func TestService_ValidateAPIKey_Expired(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createExpiredAPIKey(t, db, svc, user.ID)

	_, _, err := svc.ValidateAPIKey(context.Background(), db, rawKey)
	if err != auth.ErrAPIKeyExpired {
		t.Errorf("expected ErrAPIKeyExpired, got %v", err)
	}
}

func TestService_ValidateAPIKey_InactiveUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Key")

	// Deactivate user
	db.Model(user).Update("active", false)

	_, _, err := svc.ValidateAPIKey(context.Background(), db, rawKey)
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for inactive user, got %v", err)
	}
}

func TestService_ListAPIKeys(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	// Create multiple keys
	createTestAPIKey(t, db, svc, user.ID, "Key 1")
	createTestAPIKey(t, db, svc, user.ID, "Key 2")
	createTestAPIKey(t, db, svc, user.ID, "Key 3")

	keys, err := svc.ListAPIKeys(context.Background(), db, user.ID)
	assertNoError(t, err)
	assertEqual(t, len(keys), 3)
}

func TestService_ListAPIKeys_Empty(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	keys, err := svc.ListAPIKeys(context.Background(), db, user.ID)
	assertNoError(t, err)
	assertEqual(t, len(keys), 0)
}

func TestService_GetAPIKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	created, _ := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	key, err := svc.GetAPIKey(context.Background(), db, created.ID, user.ID)
	assertNoError(t, err)
	assertEqual(t, key.Name, "Test Key")
}

func TestService_GetAPIKey_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	_, err := svc.GetAPIKey(context.Background(), db, 99999, user.ID)
	if err != auth.ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

func TestService_GetAPIKey_WrongUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user1 := createTestUser(t, db, svc)
	user2 := createTestUserWithEmail(t, db, svc, "other@example.com")
	key, _ := createTestAPIKey(t, db, svc, user1.ID, "User1 Key")

	_, err := svc.GetAPIKey(context.Background(), db, key.ID, user2.ID)
	if err != auth.ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound for wrong user, got %v", err)
	}
}

func TestService_RevokeAPIKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	key, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	err := svc.RevokeAPIKey(context.Background(), db, key.ID, user.ID)
	assertNoError(t, err)

	// Key should no longer validate
	_, _, err = svc.ValidateAPIKey(context.Background(), db, rawKey)
	if err != auth.ErrAPIKeyRevoked {
		t.Errorf("expected ErrAPIKeyRevoked after revocation, got %v", err)
	}
}

func TestService_RevokeAPIKey_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	err := svc.RevokeAPIKey(context.Background(), db, 99999, user.ID)
	if err != auth.ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

func TestService_DeleteAPIKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	key, _ := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	err := svc.DeleteAPIKey(context.Background(), db, key.ID, user.ID)
	assertNoError(t, err)

	// Key should be gone
	_, err = svc.GetAPIKey(context.Background(), db, key.ID, user.ID)
	if err != auth.ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound after deletion, got %v", err)
	}
}

func TestService_DeleteAPIKey_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	err := svc.DeleteAPIKey(context.Background(), db, 99999, user.ID)
	if err != auth.ErrAPIKeyNotFound {
		t.Errorf("expected ErrAPIKeyNotFound, got %v", err)
	}
}

// =============================================================================
// JWT Validation Tests
// =============================================================================

func TestService_ValidateAccessToken_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	// Login to get a real token
	tokens, _, err := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)
	assertNoError(t, err)

	claims, err := svc.ValidateAccessToken(tokens.AccessToken)
	assertNoError(t, err)
	assertEqual(t, claims.UserID, user.ID)
	assertEqual(t, claims.TenantID, testTenantID)
	assertEqual(t, claims.Email, testUserEmail)
}

func TestService_ValidateAccessToken_Invalid(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	_, err := svc.ValidateAccessToken("invalid.token.here")
	if err != auth.ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestService_ValidateAccessToken_Expired(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	expiredToken := generateExpiredJWT(t, svc, user.ID, testTenantID)

	_, err := svc.ValidateAccessToken(expiredToken)
	if err != auth.ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestService_ValidateAccessToken_WrongSignature(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	// Create a token with a different secret
	otherSvc, _ := auth.New(auth.Config{
		DatabaseDir:     setupTestDir(t),
		TenantExtractor: extractors.FromCustom("static", func(c fiber.Ctx) (string, error) { return "test", nil }),
		JWTSecret:       []byte("different-secret-that-is-also-32-bytes"),
		BcryptCost:      4,
	})
	defer otherSvc.Close()

	token := generateTestJWT(t, otherSvc, 1, "test")

	_, err := svc.ValidateAccessToken(token)
	if err != auth.ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for wrong signature, got %v", err)
	}
}

// =============================================================================
// RegisterInput Validation Tests
// =============================================================================

func TestRegisterInput_Validate(t *testing.T) {
	tests := []struct {
		name    string
		input   auth.RegisterInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: auth.RegisterInput{
				Email:    "test@example.com",
				Password: "password123",
				Name:     "Test User",
			},
			wantErr: false,
		},
		{
			name: "empty email",
			input: auth.RegisterInput{
				Email:    "",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			input: auth.RegisterInput{
				Email:    "not-an-email",
				Password: "password123",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			input: auth.RegisterInput{
				Email:    "test@example.com",
				Password: "",
			},
			wantErr: true,
		},
		{
			name: "short password",
			input: auth.RegisterInput{
				Email:    "test@example.com",
				Password: "short",
			},
			wantErr: true,
		},
		{
			name: "empty name is allowed",
			input: auth.RegisterInput{
				Email:    "test@example.com",
				Password: "password123",
				Name:     "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
