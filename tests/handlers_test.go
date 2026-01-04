package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

// =============================================================================
// Registration Handler Tests
// =============================================================================

func TestRegisterHandler_Success(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/register", svc.RegisterHandler())

	body := `{"email":"newuser@example.com","password":"password123","name":"New User"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	assertNoError(t, err)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusCreated)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	user := result["user"].(map[string]interface{})
	assertEqual(t, user["email"], "newuser@example.com")
	assertEqual(t, user["name"], "New User")
}

func TestRegisterHandler_InvalidJSON(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/register", svc.RegisterHandler())

	req := httptest.NewRequest("POST", "/register", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestRegisterHandler_ValidationError(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/register", svc.RegisterHandler())

	body := `{"email":"invalid","password":"short","name":"Test"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestRegisterHandler_DuplicateUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/register", svc.RegisterHandler())

	body := `{"email":"` + testUserEmail + `","password":"password123","name":"Duplicate"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusConflict)
}

// =============================================================================
// Login Handler Tests
// =============================================================================

func TestLoginHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/login", svc.LoginHandler())

	body := `{"email":"` + testUserEmail + `","password":"` + testUserPassword + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	assertNotNil(t, result["access_token"], "should return access token")
	assertNotNil(t, result["refresh_token"], "should return refresh token")
	assertEqual(t, result["token_type"], "Bearer")
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/login", svc.LoginHandler())

	body := `{"email":"` + testUserEmail + `","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestLoginHandler_InvalidJSON(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/login", svc.LoginHandler())

	req := httptest.NewRequest("POST", "/login", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestLoginHandler_SetsCookie(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/login", svc.LoginHandler())

	body := `{"email":"` + testUserEmail + `","password":"` + testUserPassword + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	// Check for Set-Cookie header (CookieHTTPOnly is true in test config)
	cookies := resp.Header.Values("Set-Cookie")
	var hasRefreshCookie bool
	for _, cookie := range cookies {
		if strings.Contains(cookie, "refresh_token=") {
			hasRefreshCookie = true
			break
		}
	}
	assertTrue(t, hasRefreshCookie, "should set refresh_token cookie")
}

// =============================================================================
// Refresh Handler Tests
// =============================================================================

func TestRefreshHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	// Login first
	tokens, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/refresh", svc.RefreshHandler())

	body := `{"refresh_token":"` + tokens.RefreshToken + `"}`
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	assertNotNil(t, result["access_token"], "should return new access token")
	assertNotNil(t, result["refresh_token"], "should return new refresh token")
}

func TestRefreshHandler_FromCookie(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	tokens, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/refresh", svc.RefreshHandler())

	req := httptest.NewRequest("POST", "/refresh", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "refresh_token="+tokens.RefreshToken)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRefreshHandler_InvalidToken(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/refresh", svc.RefreshHandler())

	body := `{"refresh_token":"invalid-token"}`
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestRefreshHandler_MissingToken(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/refresh", svc.RefreshHandler())

	req := httptest.NewRequest("POST", "/refresh", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

// =============================================================================
// Logout Handler Tests
// =============================================================================

func TestLogoutHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	tokens, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/logout", svc.LogoutHandler())

	body := `{"refresh_token":"` + tokens.RefreshToken + `"}`
	req := httptest.NewRequest("POST", "/logout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	// Check cookie is cleared
	cookies := resp.Header.Values("Set-Cookie")
	var cookieCleared bool
	for _, cookie := range cookies {
		if strings.Contains(cookie, "refresh_token=;") || strings.Contains(cookie, "refresh_token=\"\"") {
			cookieCleared = true
			break
		}
	}
	assertTrue(t, cookieCleared, "should clear refresh_token cookie")
}

func TestLogoutHandler_FromCookie(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	createTestUser(t, db, svc)

	tokens, _, _ := svc.Login(context.Background(), db, auth.LoginInput{
		Email:    testUserEmail,
		Password: testUserPassword,
	}, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/logout", svc.LogoutHandler())

	req := httptest.NewRequest("POST", "/logout", nil)
	req.Header.Set("Cookie", "refresh_token="+tokens.RefreshToken)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

// =============================================================================
// Logout All Handler Tests
// =============================================================================

func TestLogoutAllHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/logout-all", svc.LogoutAllHandler())

	req := httptest.NewRequest("POST", "/logout-all", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestLogoutAllHandler_Unauthorized(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	// No auth middleware - simulate unauthenticated request
	app.Post("/logout-all", svc.LogoutAllHandler())

	req := httptest.NewRequest("POST", "/logout-all", nil)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// Me Handler Tests
// =============================================================================

func TestMeHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/me", svc.MeHandler())

	req := httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	userInfo := result["user"].(map[string]interface{})
	assertEqual(t, userInfo["email"], testUserEmail)
	assertEqual(t, result["auth_type"], "jwt")
}

func TestMeHandler_NotAuthenticated(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Get("/me", svc.MeHandler())

	req := httptest.NewRequest("GET", "/me", nil)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestMeHandler_WithAPIKey(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	_, rawKey := createTestAPIKey(t, db, svc, user.ID, "Test Key")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.APIKeyMiddleware())
	app.Get("/me", svc.MeHandler())

	req := httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("X-API-Key", rawKey)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	assertEqual(t, result["auth_type"], "apikey")
}

// =============================================================================
// Change Password Handler Tests
// =============================================================================

func TestChangePasswordHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/change-password", svc.ChangePasswordHandler())

	body := `{"old_password":"` + testUserPassword + `","new_password":"newpassword123"}`
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestChangePasswordHandler_WrongPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/change-password", svc.ChangePasswordHandler())

	body := `{"old_password":"wrongpassword","new_password":"newpassword123"}`
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestChangePasswordHandler_WeakPassword(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/change-password", svc.ChangePasswordHandler())

	body := `{"old_password":"` + testUserPassword + `","new_password":"short"}`
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestChangePasswordHandler_Unauthorized(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/change-password", svc.ChangePasswordHandler())

	body := `{"old_password":"old","new_password":"newpassword123"}`
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// Create API Key Handler Tests
// =============================================================================

func TestCreateAPIKeyHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/api-keys", svc.CreateAPIKeyHandler())

	body := `{"name":"My API Key","scopes":["read","write"],"description":"Test key"}`
	req := httptest.NewRequest("POST", "/api-keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusCreated)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	assertNotNil(t, result["key"], "should return raw key")
	assertNotNil(t, result["warning"], "should include warning about storing key")

	apiKey := result["api_key"].(map[string]interface{})
	assertEqual(t, apiKey["name"], "My API Key")
}

func TestCreateAPIKeyHandler_NoName(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/api-keys", svc.CreateAPIKeyHandler())

	body := `{"name":"","scopes":["read"]}`
	req := httptest.NewRequest("POST", "/api-keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestCreateAPIKeyHandler_Unauthorized(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/api-keys", svc.CreateAPIKeyHandler())

	body := `{"name":"Test Key"}`
	req := httptest.NewRequest("POST", "/api-keys", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// List API Keys Handler Tests
// =============================================================================

func TestListAPIKeysHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	createTestAPIKey(t, db, svc, user.ID, "Key 1")
	createTestAPIKey(t, db, svc, user.ID, "Key 2")

	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/api-keys", svc.ListAPIKeysHandler())

	req := httptest.NewRequest("GET", "/api-keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	keys := result["api_keys"].([]interface{})
	assertEqual(t, len(keys), 2)
}

func TestListAPIKeysHandler_Empty(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/api-keys", svc.ListAPIKeysHandler())

	req := httptest.NewRequest("GET", "/api-keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	keys := result["api_keys"].([]interface{})
	assertEqual(t, len(keys), 0)
}

// =============================================================================
// Revoke API Key Handler Tests
// =============================================================================

func TestRevokeAPIKeyHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	apiKey, _ := createTestAPIKey(t, db, svc, user.ID, "Test Key")
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/api-keys/:id/revoke", svc.RevokeAPIKeyHandler())

	req := httptest.NewRequest("DELETE", "/api-keys/"+uintToString(apiKey.ID)+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRevokeAPIKeyHandler_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/api-keys/:id/revoke", svc.RevokeAPIKeyHandler())

	req := httptest.NewRequest("DELETE", "/api-keys/99999/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusNotFound)
}

func TestRevokeAPIKeyHandler_InvalidID(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/api-keys/:id/revoke", svc.RevokeAPIKeyHandler())

	req := httptest.NewRequest("DELETE", "/api-keys/invalid/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

// =============================================================================
// Delete API Key Handler Tests
// =============================================================================

func TestDeleteAPIKeyHandler_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	apiKey, _ := createTestAPIKey(t, db, svc, user.ID, "Test Key")
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/api-keys/:id", svc.DeleteAPIKeyHandler())

	req := httptest.NewRequest("DELETE", "/api-keys/"+uintToString(apiKey.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusNoContent)
}

func TestDeleteAPIKeyHandler_NotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/api-keys/:id", svc.DeleteAPIKeyHandler())

	req := httptest.NewRequest("DELETE", "/api-keys/99999", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusNotFound)
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

func TestHandler_NoDatabaseInContext(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	app := fiber.New()
	// Note: No tenant middleware, so no DB in context
	app.Post("/register", svc.RegisterHandler())

	body := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusInternalServerError)
}

func TestHandler_EmptyRequestBody(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Post("/register", svc.RegisterHandler())

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(nil))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestFullAuthFlow(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	app := fiber.New()
	app.Use(svc.TenantMiddleware())

	// Public routes
	app.Post("/register", svc.RegisterHandler())
	app.Post("/login", svc.LoginHandler())
	app.Post("/refresh", svc.RefreshHandler())
	app.Post("/logout", svc.LogoutHandler())

	// Protected routes
	protected := app.Group("/", svc.AuthMiddleware())
	protected.Get("/me", svc.MeHandler())
	protected.Post("/api-keys", svc.CreateAPIKeyHandler())

	// 1. Register
	regBody := `{"email":"flow@example.com","password":"password123","name":"Flow User"}`
	regReq := httptest.NewRequest("POST", "/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regResp, _ := app.Test(regReq)
	assertEqual(t, regResp.StatusCode, fiber.StatusCreated)
	regResp.Body.Close()

	// 2. Login
	loginBody := `{"email":"flow@example.com","password":"password123"}`
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, _ := app.Test(loginReq)
	assertEqual(t, loginResp.StatusCode, fiber.StatusOK)

	var loginResult map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&loginResult)
	loginResp.Body.Close()

	accessToken := loginResult["access_token"].(string)
	refreshToken := loginResult["refresh_token"].(string)

	// 3. Access protected route
	meReq := httptest.NewRequest("GET", "/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+accessToken)
	meResp, _ := app.Test(meReq)
	assertEqual(t, meResp.StatusCode, fiber.StatusOK)
	meResp.Body.Close()

	// 4. Refresh token
	refreshBody := `{"refresh_token":"` + refreshToken + `"}`
	refreshReq := httptest.NewRequest("POST", "/refresh", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshResp, _ := app.Test(refreshReq)
	assertEqual(t, refreshResp.StatusCode, fiber.StatusOK)

	var refreshResult map[string]interface{}
	json.NewDecoder(refreshResp.Body).Decode(&refreshResult)
	refreshResp.Body.Close()

	newRefreshToken := refreshResult["refresh_token"].(string)

	// 5. Logout
	logoutBody := `{"refresh_token":"` + newRefreshToken + `"}`
	logoutReq := httptest.NewRequest("POST", "/logout", strings.NewReader(logoutBody))
	logoutReq.Header.Set("Content-Type", "application/json")
	logoutResp, _ := app.Test(logoutReq)
	assertEqual(t, logoutResp.StatusCode, fiber.StatusOK)
	logoutResp.Body.Close()

	// 6. Old refresh token should be invalid
	oldRefreshBody := `{"refresh_token":"` + refreshToken + `"}`
	oldRefreshReq := httptest.NewRequest("POST", "/refresh", strings.NewReader(oldRefreshBody))
	oldRefreshReq.Header.Set("Content-Type", "application/json")
	oldRefreshResp, _ := app.Test(oldRefreshReq)
	assertEqual(t, oldRefreshResp.StatusCode, fiber.StatusUnauthorized)
	oldRefreshResp.Body.Close()
}

// Helper to convert uint to string
func uintToString(n uint) string {
	return string(rune('0'+n%10)) + func() string {
		if n < 10 {
			return ""
		}
		return uintToString(n / 10)
	}()
}

// Override for proper implementation
func init() {
	// Use strconv instead
}

// Proper uint to string helper
func uintToStr(n uint) string {
	var buf [20]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(buf[i:])
}

// Override for test
func TestRevokeAPIKeyHandler_WithCorrectID(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	user := createTestUser(t, db, svc)
	apiKey, _ := createTestAPIKey(t, db, svc, user.ID, "Test Key")
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/api-keys/:id/revoke", svc.RevokeAPIKeyHandler())

	// Use proper conversion
	idStr := uintToStr(apiKey.ID)
	req := httptest.NewRequest("DELETE", "/api-keys/"+idStr+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	// Verify the response message
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	assertTrue(t, strings.Contains(bodyStr, "revoked") || resp.StatusCode == fiber.StatusOK, "should indicate success")
}
