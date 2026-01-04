package tests

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

// =============================================================================
// Tenant Middleware Tests
// =============================================================================

func TestTenantMiddleware_Success(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		tenantID := auth.GetTenantID(c)
		db := auth.GetTenantDB(c)
		return c.JSON(fiber.Map{
			"tenant_id": tenantID,
			"has_db":    db != nil,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// Static extractor always returns testTenantID
	resp, err := app.Test(req)
	assertNoError(t, err)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestTenantMiddleware_NoTenant(t *testing.T) {
	config := auth.DefaultConfig()
	config.DatabaseDir = "./test_data/tenants"
	config.JWTSecret = []byte("test-secret-key-at-least-32-bytes-long")
	config.TenantExtractor = extractors.FromHeader("X-Tenant-ID") // Requires header
	svc, err := auth.New(config)
	assertNoError(t, err)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No X-Tenant-ID header
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestTenantMiddleware_EmptyTenant(t *testing.T) {
	config := setupTestConfig(t)
	config.TenantExtractor = extractors.FromCustom("whitespace", func(c fiber.Ctx) (string, error) {
		return "   ", nil // Whitespace only
	})
	svc, err := auth.New(config)
	assertNoError(t, err)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestTenantMiddleware_TenantNotFound(t *testing.T) {
	config := setupTestConfig(t)
	config.AllowTenantCreation = false
	config.TenantExtractor = extractors.FromCustom("static", func(c fiber.Ctx) (string, error) { return "nonexistent-tenant", nil })
	svc, err := auth.New(config)
	assertNoError(t, err)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusNotFound)
}

// =============================================================================
// JWT Middleware Tests
// =============================================================================

func TestJWTMiddleware_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		claims := auth.GetClaims(c)
		return c.JSON(fiber.Map{
			"user_id": claims.UserID,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestJWTMiddleware_TenantMismatch(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	// Generate token for different tenant
	token := generateTestJWT(t, svc, user.ID, "different-tenant")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestJWTMiddleware_UserNotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	// Create token for non-existent user
	token := generateTestJWT(t, svc, 99999, testTenantID)

	// Ensure tenant DB exists
	svc.DatabaseManager().GetDB(context.Background(), testTenantID)
	_ = db // Silence unused variable warning

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestJWTMiddleware_UserInactive(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	// Deactivate user
	db.Model(user).Update("active", false)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// API Key Middleware Tests
// =============================================================================

func TestAPIKeyMiddleware_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		apiKey := auth.GetAPIKey(c)
		return c.JSON(fiber.Map{
			"key_name": apiKey.Name,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestAPIKeyMiddleware_ApiKeyScheme(t *testing.T) {
	// Test that API keys can be passed via "Authorization: ApiKey <key>" scheme
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// API keys are passed with ApiKey scheme in Authorization header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "ApiKey "+rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestAPIKeyMiddleware_ExpiredKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createExpiredAPIKey(t, db, svc, user.ID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestAPIKeyMiddleware_RevokedKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	apiKey, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	// Revoke the key
	svc.RevokeAPIKey(context.Background(), db, apiKey.ID, user.ID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// Combined Auth Middleware Tests
// =============================================================================

func TestAuthMiddleware_JWT(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.AuthMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"auth_type": auth.GetAuthType(c),
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"auth_type":"jwt"`) {
		t.Errorf("expected auth_type jwt, got %s", string(body))
	}
}

func TestAuthMiddleware_APIKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.AuthMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"auth_type": auth.GetAuthType(c),
		})
	})

	// API keys via X-API-Key header (secure method)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"auth_type":"apikey"`) {
		t.Errorf("expected auth_type apikey, got %s", string(body))
	}
}

func TestAuthMiddleware_NoAuth(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.AuthMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	// No auth headers
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// RequireRole Tests
// =============================================================================

func TestRequireRole_HasRole(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	db.Model(user).Update("role", "admin")
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Use(auth.RequireRole("admin", "superadmin"))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRequireRole_NoRole(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	// user.Role is "user" by default
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Use(auth.RequireRole("admin"))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestRequireRole_NoUser(t *testing.T) {
	app := fiber.New()
	app.Use(auth.RequireRole("admin"))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// RequireScope Tests
// =============================================================================

func TestRequireScope_HasScope(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Use(auth.RequireScope("read"))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRequireScope_NoScope(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)

	// Create key without the required scope
	result, err := svc.CreateAPIKey(context.Background(), db, user.ID, auth.CreateAPIKeyInput{
		Name:   "Limited Key",
		Scopes: []string{"read"},
	})
	assertNoError(t, err)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Use(auth.RequireScope("admin"))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", result.RawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestRequireScope_NotAPIKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Use(auth.RequireScope("admin"))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	// JWT auth should pass through RequireScope
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

// =============================================================================
// Context Helper Tests
// =============================================================================

func TestContextHelpers(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		// Test all context helpers
		tenantID := auth.GetTenantID(c)
		tenantDB := auth.GetTenantDB(c)
		authUser := auth.GetUser(c)
		userID := auth.GetUserID(c)
		apiKey := auth.GetAPIKey(c)
		authType := auth.GetAuthType(c)
		authenticated := auth.IsAuthenticated(c)

		return c.JSON(fiber.Map{
			"tenant_id":     tenantID,
			"has_db":        tenantDB != nil,
			"user_email":    authUser.Email,
			"user_id":       userID,
			"key_name":      apiKey.Name,
			"auth_type":     authType,
			"authenticated": authenticated,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestContextHelpers_NoAuth(t *testing.T) {
	app := fiber.New()
	app.Get("/test", func(c fiber.Ctx) error {
		// All should return zero values
		tenantID := auth.GetTenantID(c)
		tenantDB := auth.GetTenantDB(c)
		user := auth.GetUser(c)
		userID := auth.GetUserID(c)
		apiKey := auth.GetAPIKey(c)
		claims := auth.GetClaims(c)
		authType := auth.GetAuthType(c)
		authenticated := auth.IsAuthenticated(c)

		return c.JSON(fiber.Map{
			"tenant_id":     tenantID,
			"has_db":        tenantDB != nil,
			"has_user":      user != nil,
			"user_id":       userID,
			"has_api_key":   apiKey != nil,
			"has_claims":    claims != nil,
			"auth_type":     authType,
			"authenticated": authenticated,
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify zero values
	if !strings.Contains(bodyStr, `"tenant_id":""`) {
		t.Errorf("expected empty tenant_id, got %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"has_db":false`) {
		t.Errorf("expected has_db false, got %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"has_user":false`) {
		t.Errorf("expected has_user false, got %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"user_id":0`) {
		t.Errorf("expected user_id 0, got %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"authenticated":false`) {
		t.Errorf("expected authenticated false, got %s", bodyStr)
	}
}

// =============================================================================
// Callback Tests
// =============================================================================

func TestOnAuthSuccess_Callback(t *testing.T) {
	var callbackCalled bool
	var callbackAuthType string
	var callbackUserID uint

	config := setupTestConfig(t)
	config.OnAuthSuccess = func(c fiber.Ctx, authType string, userID uint) {
		callbackCalled = true
		callbackAuthType = authType
		callbackUserID = userID
	}

	svc, err := auth.New(config)
	assertNoError(t, err)
	defer svc.Close()

	db, _ := svc.DatabaseManager().GetDB(context.Background(), testTenantID)
	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	resp.Body.Close()

	assertTrue(t, callbackCalled, "OnAuthSuccess callback should be called")
	assertEqual(t, callbackAuthType, auth.AuthTypeJWT)
	assertEqual(t, callbackUserID, user.ID)
}

func TestOnAuthFailure_Callback(t *testing.T) {
	var callbackCalled bool
	var callbackError error

	config := setupTestConfig(t)
	config.OnAuthFailure = func(c fiber.Ctx, err error) {
		callbackCalled = true
		callbackError = err
	}

	svc, err := auth.New(config)
	assertNoError(t, err)
	defer svc.Close()

	// Ensure tenant exists
	svc.DatabaseManager().GetDB(context.Background(), testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	resp, _ := app.Test(req)
	resp.Body.Close()

	assertTrue(t, callbackCalled, "OnAuthFailure callback should be called")
	assertNotNil(t, callbackError, "callback should receive error")
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestAuthMiddleware_NonBearerAuthorization(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.AuthMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"auth_type": auth.GetAuthType(c),
		})
	})

	// Test with X-API-Key header (secure method for API keys)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	// Should use API key auth since the token doesn't look like a JWT
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRefreshTokenCookie(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	// Login to get tokens (which sets cookie if CookieHTTPOnly is true)
	loginTokens, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/refresh", svc.RefreshHandler())

	// Test refresh using cookie
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "refresh_token="+loginTokens.RefreshToken)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestExpiredToken(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	expiredToken := generateExpiredJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestAPIKeyUpdatesLastUsed(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	apiKey, rawKey := createTestAPIKey(t, db, svc, user.ID, "Tracking Key")

	// Verify last_used_at is nil initially
	if apiKey.LastUsedAt != nil {
		t.Error("LastUsedAt should be nil before first use")
	}

	// Make a request
	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", rawKey)
	resp, _ := app.Test(req)
	resp.Body.Close()

	// Check that last_used_at was updated
	var updatedKey auth.APIKey
	db.First(&updatedKey, apiKey.ID)

	assertNotNil(t, updatedKey.LastUsedAt, "LastUsedAt should be set after use")
	assertTrue(t, updatedKey.UsageCount > 0, "UsageCount should be incremented")

	// Verify it's a recent timestamp
	if time.Since(*updatedKey.LastUsedAt) > time.Minute {
		t.Error("LastUsedAt should be recent")
	}
}
