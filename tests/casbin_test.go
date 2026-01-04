package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

// =============================================================================
// Authorizer Creation Tests
// =============================================================================

func TestNewAuthorizer_Success(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)
	assertNotNil(t, authorizer, "authorizer should not be nil")
}

func TestNewAuthorizer_CustomConfig(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	config := auth.CasbinConfig{
		ModelText: auth.DefaultRBACModel,
		Unauthorized: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "custom unauthorized",
			})
		},
		Forbidden: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "custom forbidden",
			})
		},
	}

	authorizer, err := svc.NewAuthorizer(config)
	assertNoError(t, err)
	assertNotNil(t, authorizer, "authorizer should not be nil")
}

func TestNewAuthorizer_InvalidModel(t *testing.T) {
	svc := setupTestService(t)
	defer svc.Close()

	config := auth.CasbinConfig{
		ModelText: "invalid model text",
	}

	_, err := svc.NewAuthorizer(config)
	if err == nil {
		t.Error("expected error for invalid model")
	}
}

// =============================================================================
// Policy Management Tests
// =============================================================================

func TestAddPolicy(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add a policy
	added, err := authorizer.AddPolicy(db, testTenantID, subject, "/api/blog", "GET")
	assertNoError(t, err)
	assertTrue(t, added, "policy should be added")

	// Verify policy exists
	policies, err := authorizer.GetPolicies(db, testTenantID)
	assertNoError(t, err)

	found := false
	for _, p := range policies {
		if len(p) >= 4 && p[0] == subject && p[1] == testTenantID && p[2] == "/api/blog" && p[3] == "GET" {
			found = true
			break
		}
	}
	assertTrue(t, found, "added policy should be in policy list")
}

func TestRemovePolicy(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add and then remove a policy
	authorizer.AddPolicy(db, testTenantID, subject, "/api/blog", "GET")

	removed, err := authorizer.RemovePolicy(db, testTenantID, subject, "/api/blog", "GET")
	assertNoError(t, err)
	assertTrue(t, removed, "policy should be removed")

	// Verify policy is gone
	policies, err := authorizer.GetPolicies(db, testTenantID)
	assertNoError(t, err)

	for _, p := range policies {
		if len(p) >= 4 && p[0] == subject && p[2] == "/api/blog" {
			t.Error("removed policy should not exist")
		}
	}
}

func TestAddDuplicatePolicy(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add same policy twice
	added1, _ := authorizer.AddPolicy(db, testTenantID, subject, "/api/blog", "GET")
	added2, _ := authorizer.AddPolicy(db, testTenantID, subject, "/api/blog", "GET")

	assertTrue(t, added1, "first add should succeed")
	assertFalse(t, added2, "duplicate add should return false")
}

// =============================================================================
// Role Assignment Tests
// =============================================================================

func TestAddRoleForUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)

	// Assign role
	added, err := authorizer.AddRoleForUser(db, testTenantID, user.ID, "admin")
	assertNoError(t, err)
	assertTrue(t, added, "role should be assigned")

	// Verify role
	roles, err := authorizer.GetRolesForUser(db, testTenantID, user.ID)
	assertNoError(t, err)

	found := false
	for _, r := range roles {
		if r == "admin" {
			found = true
			break
		}
	}
	assertTrue(t, found, "user should have admin role")
}

func TestRemoveRoleForUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)

	// Add and remove role
	authorizer.AddRoleForUser(db, testTenantID, user.ID, "editor")
	removed, err := authorizer.RemoveRoleForUser(db, testTenantID, user.ID, "editor")
	assertNoError(t, err)
	assertTrue(t, removed, "role should be removed")

	// Verify role is gone
	roles, err := authorizer.GetRolesForUser(db, testTenantID, user.ID)
	assertNoError(t, err)

	for _, r := range roles {
		if r == "editor" {
			t.Error("removed role should not exist")
		}
	}
}

func TestGetUsersForRole(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user1 := createTestUserWithEmail(t, db, svc, "user1@example.com")
	user2 := createTestUserWithEmail(t, db, svc, "user2@example.com")

	// Assign same role to both users
	authorizer.AddRoleForUser(db, testTenantID, user1.ID, "moderator")
	authorizer.AddRoleForUser(db, testTenantID, user2.ID, "moderator")

	users, err := authorizer.GetUsersForRole(db, testTenantID, "moderator")
	assertNoError(t, err)
	assertEqual(t, len(users), 2)
}

// =============================================================================
// Permission Check Tests
// =============================================================================

func TestHasPermission_DirectPolicy(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add direct permission
	authorizer.AddPolicy(db, testTenantID, subject, "/api/posts", "GET")

	// Check permission
	hasPermission, err := authorizer.HasPermission(db, testTenantID, user.ID, "/api/posts", "GET")
	assertNoError(t, err)
	assertTrue(t, hasPermission, "user should have permission")

	// Check non-existent permission
	hasPermission, err = authorizer.HasPermission(db, testTenantID, user.ID, "/api/posts", "DELETE")
	assertNoError(t, err)
	assertFalse(t, hasPermission, "user should not have DELETE permission")
}

func TestHasPermission_ViaRole(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)

	// Add policy for role
	authorizer.AddPolicyForRole(db, testTenantID, "admin", "/api/admin/*", "*")
	// Assign role to user
	authorizer.AddRoleForUser(db, testTenantID, user.ID, "admin")

	// Check inherited permission
	hasPermission, err := authorizer.HasPermission(db, testTenantID, user.ID, "/api/admin/users", "GET")
	assertNoError(t, err)
	assertTrue(t, hasPermission, "user should inherit admin permission")
}

func TestGetPermissionsForUser(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add direct policy
	authorizer.AddPolicy(db, testTenantID, subject, "/api/blog", "GET")
	// Add role policy
	authorizer.AddPolicyForRole(db, testTenantID, "writer", "/api/posts", "POST")
	authorizer.AddRoleForUser(db, testTenantID, user.ID, "writer")

	// Get all permissions (direct + inherited)
	permissions, err := authorizer.GetPermissionsForUser(db, testTenantID, user.ID)
	assertNoError(t, err)
	assertTrue(t, len(permissions) >= 2, "user should have at least 2 permissions")
}

// =============================================================================
// Multi-Tenant Isolation Tests
// =============================================================================

func TestMultiTenantIsolation(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add policy for tenant1
	authorizer.AddPolicy(db, testTenantID, subject, "/api/data", "GET")

	// Check permission for correct tenant
	hasPermission, _ := authorizer.HasPermission(db, testTenantID, user.ID, "/api/data", "GET")
	assertTrue(t, hasPermission, "should have permission in own tenant")

	// Check permission for different tenant (should fail)
	hasPermission, _ = authorizer.HasPermission(db, "different-tenant", user.ID, "/api/data", "GET")
	assertFalse(t, hasPermission, "should not have permission in different tenant")
}

// =============================================================================
// Middleware Tests
// =============================================================================

func TestRequiresPermissions_SinglePermission(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add permission
	authorizer.AddPolicy(db, testTenantID, subject, "blog:create", "*")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/blog", authorizer.RequiresPermissions([]string{"blog:create"}), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "created"})
	})

	req := httptest.NewRequest("POST", "/blog", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRequiresPermissions_NoPermission(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	// Don't add any permission

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/blog", authorizer.RequiresPermissions([]string{"blog:create"}), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "created"})
	})

	req := httptest.NewRequest("POST", "/blog", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestRequiresPermissions_MatchAllRule(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add only one of two required permissions
	authorizer.AddPolicy(db, testTenantID, subject, "blog:read", "*")
	// Missing blog:delete

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Delete("/blog/:id",
		authorizer.RequiresPermissions(
			[]string{"blog:read", "blog:delete"},
			auth.WithValidationRule(auth.MatchAllRule),
		),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "deleted"})
		})

	req := httptest.NewRequest("DELETE", "/blog/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestRequiresPermissions_AtLeastOneRule(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add only one of two possible permissions
	authorizer.AddPolicy(db, testTenantID, subject, "blog:edit", "*")
	// Don't add blog:admin

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Put("/blog/:id",
		authorizer.RequiresPermissions(
			[]string{"blog:edit", "blog:admin"},
			auth.WithValidationRule(auth.AtLeastOneRule),
		),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "updated"})
		})

	req := httptest.NewRequest("PUT", "/blog/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	// Should pass because user has blog:edit
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRequiresRoles_HasRole(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	// Assign role via Casbin
	authorizer.AddRoleForUser(db, testTenantID, user.ID, "editor")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/editor/dashboard",
		authorizer.RequiresRoles([]string{"editor", "admin"}),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "editor dashboard"})
		})

	req := httptest.NewRequest("GET", "/editor/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRequiresRoles_NoRole(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	// Don't assign any role

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/admin",
		authorizer.RequiresRoles([]string{"admin"}),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "admin area"})
		})

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestRequiresRoles_MatchAllRule(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	// Assign only one of two required roles
	authorizer.AddRoleForUser(db, testTenantID, user.ID, "admin")
	// Don't assign "super" role

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/super-admin",
		authorizer.RequiresRoles(
			[]string{"admin", "super"},
			auth.WithValidationRule(auth.MatchAllRule),
		),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "super admin"})
		})

	req := httptest.NewRequest("GET", "/super-admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	// Should fail because user only has admin, not super
	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
}

func TestRoutePermission(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add route-based permission
	authorizer.AddPolicy(db, testTenantID, subject, "/api/blog", "GET")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/api/blog", authorizer.RoutePermission(), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "blog list"})
	})

	req := httptest.NewRequest("GET", "/api/blog", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)
}

func TestRoutePermission_Wildcard(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add wildcard permission for all methods
	authorizer.AddPolicy(db, testTenantID, subject, "/api/posts/*", "*")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/api/posts/:id", authorizer.RoutePermission(), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"id": c.Params("id")})
	})
	app.Delete("/api/posts/:id", authorizer.RoutePermission(), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"deleted": c.Params("id")})
	})

	// Test GET
	req := httptest.NewRequest("GET", "/api/posts/123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
	resp.Body.Close()

	// Test DELETE
	req = httptest.NewRequest("DELETE", "/api/posts/123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = app.Test(req)
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
	resp.Body.Close()
}

// =============================================================================
// Handler Tests
// =============================================================================

func TestAddPolicyHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	db.Model(user).Update("role", "admin")
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/policies", auth.RequireRole("admin"), authorizer.AddPolicyHandler())

	body := `{"subject":"user:1","object":"/api/test","action":"GET"}`
	req := httptest.NewRequest("POST", "/policies", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusCreated)
}

func TestListPoliciesHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	db.Model(user).Update("role", "admin")
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add some policies
	authorizer.AddPolicy(db, testTenantID, subject, "/api/a", "GET")
	authorizer.AddPolicy(db, testTenantID, subject, "/api/b", "POST")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/policies", auth.RequireRole("admin"), authorizer.ListPoliciesHandler())

	req := httptest.NewRequest("GET", "/policies", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "policies") {
		t.Errorf("response should contain policies, got %s", string(body))
	}
}

func TestAssignRoleHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	admin := createTestUserWithEmail(t, db, svc, "admin@example.com")
	db.Model(admin).Update("role", "admin")
	token := generateTestJWT(t, svc, admin.ID, testTenantID)

	targetUser := createTestUserWithEmail(t, db, svc, "target@example.com")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/roles/assign", auth.RequireRole("admin"), authorizer.AssignRoleHandler())

	body := fmt.Sprintf(`{"user_id":%d,"role":"editor"}`, targetUser.ID)
	req := httptest.NewRequest("POST", "/roles/assign", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusCreated)

	// Verify role was assigned
	roles, _ := authorizer.GetRolesForUser(db, testTenantID, targetUser.ID)
	found := false
	for _, r := range roles {
		if r == "editor" {
			found = true
		}
	}
	assertTrue(t, found, "user should have editor role")
}

func TestGetUserRolesHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	admin := createTestUserWithEmail(t, db, svc, "admin@example.com")
	db.Model(admin).Update("role", "admin")
	token := generateTestJWT(t, svc, admin.ID, testTenantID)

	targetUser := createTestUserWithEmail(t, db, svc, "target@example.com")
	authorizer.AddRoleForUser(db, testTenantID, targetUser.ID, "reader")
	authorizer.AddRoleForUser(db, testTenantID, targetUser.ID, "writer")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/roles/user/:id", auth.RequireRole("admin"), authorizer.GetUserRolesHandler())

	req := httptest.NewRequest("GET", fmt.Sprintf("/roles/user/%d", targetUser.ID), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "reader") || !strings.Contains(bodyStr, "writer") {
		t.Errorf("response should contain roles, got %s", bodyStr)
	}
}

func TestGetMyPermissionsHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add permissions and roles
	authorizer.AddPolicy(db, testTenantID, subject, "/api/my-resource", "GET")
	authorizer.AddRoleForUser(db, testTenantID, user.ID, "member")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Get("/permissions/me", authorizer.GetMyPermissionsHandler())

	req := httptest.NewRequest("GET", "/permissions/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "permissions") || !strings.Contains(bodyStr, "roles") {
		t.Errorf("response should contain permissions and roles, got %s", bodyStr)
	}
}

func TestCheckPermissionHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	token := generateTestJWT(t, svc, user.ID, testTenantID)
	subject := fmt.Sprintf("user:%d", user.ID)

	authorizer.AddPolicy(db, testTenantID, subject, "/api/check-test", "GET")

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/permissions/check", authorizer.CheckPermissionHandler())

	body := fmt.Sprintf(`{"user_id":%d,"object":"/api/check-test","action":"GET"}`, user.ID)
	req := httptest.NewRequest("POST", "/permissions/check", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusOK)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	assertTrue(t, result["allowed"].(bool), "permission should be allowed")
}

// =============================================================================
// Bulk Operations Tests
// =============================================================================

func TestAddBulkPolicies(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	rules := [][]string{
		{"user:1", "/api/a", "GET"},
		{"user:1", "/api/b", "POST"},
		{"user:2", "/api/c", "DELETE"},
	}

	added, err := authorizer.AddPolicies(db, testTenantID, rules)
	assertNoError(t, err)
	assertTrue(t, added, "bulk policies should be added")

	policies, _ := authorizer.GetPolicies(db, testTenantID)
	assertTrue(t, len(policies) >= 3, "should have at least 3 policies")
}

func TestClearAllPolicies(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	// Add some policies
	authorizer.AddPolicy(db, testTenantID, "user:1", "/api/x", "GET")
	authorizer.AddPolicy(db, testTenantID, "user:2", "/api/y", "POST")
	authorizer.AddRoleForUser(db, testTenantID, 1, "admin")

	// Clear all
	err = authorizer.ClearAllPolicies(db, testTenantID)
	assertNoError(t, err)

	// Verify empty
	policies, _ := authorizer.GetPolicies(db, testTenantID)
	tenantPolicies := 0
	for _, p := range policies {
		if len(p) >= 2 && p[1] == testTenantID {
			tenantPolicies++
		}
	}
	assertEqual(t, tenantPolicies, 0)
}

// =============================================================================
// Handler Validation Tests
// =============================================================================

func TestAddPolicyHandler_InvalidBody(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	db.Model(user).Update("role", "admin")
	token := generateTestJWT(t, svc, user.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/policies", auth.RequireRole("admin"), authorizer.AddPolicyHandler())

	// Missing required fields
	body := `{"subject":"user:1"}`
	req := httptest.NewRequest("POST", "/policies", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusBadRequest)
}

func TestAssignRoleHandler_UserNotFound(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	admin := createTestUser(t, db, svc)
	db.Model(admin).Update("role", "admin")
	token := generateTestJWT(t, svc, admin.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/roles/assign", auth.RequireRole("admin"), authorizer.AssignRoleHandler())

	body := `{"user_id":99999,"role":"editor"}`
	req := httptest.NewRequest("POST", "/roles/assign", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusNotFound)
}

// =============================================================================
// Unauthorized/Forbidden Response Tests
// =============================================================================

func TestRequiresPermissions_Unauthorized(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	// No auth middleware - user not authenticated
	app.Get("/test", authorizer.RequiresPermissions([]string{"test:read"}), func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

func TestRoutePermission_Unauthorized(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	// No auth middleware
	app.Get("/test", authorizer.RoutePermission(), func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusUnauthorized)
}

// =============================================================================
// Integration Test
// =============================================================================

func TestFullAuthorizationFlow(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	// Create admin and regular user
	admin := createTestUserWithEmail(t, db, svc, "admin@test.com")
	db.Model(admin).Update("role", "admin")
	adminToken := generateTestJWT(t, svc, admin.ID, testTenantID)

	regularUser := createTestUserWithEmail(t, db, svc, "user@test.com")
	userToken := generateTestJWT(t, svc, regularUser.ID, testTenantID)

	// Admin assigns role to regular user
	authorizer.AddRoleForUser(db, testTenantID, regularUser.ID, "blogger")

	// Add policy for blogger role
	authorizer.AddPolicyForRole(db, testTenantID, "blogger", "blog:*", "*")

	// Setup app with routes
	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())

	app.Post("/blog", authorizer.RequiresPermissions([]string{"blog:create"}), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "blog created"})
	})

	app.Get("/admin", authorizer.RequiresRoles([]string{"admin"}), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "admin panel"})
	})

	// Test 1: Regular user can create blog (has blogger role with blog:* permission)
	req := httptest.NewRequest("POST", "/blog", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, _ := app.Test(req)
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
	resp.Body.Close()

	// Test 2: Regular user cannot access admin panel
	req = httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, _ = app.Test(req)
	assertEqual(t, resp.StatusCode, fiber.StatusForbidden)
	resp.Body.Close()

	// Test 3: Admin user can access admin panel (assign admin role via Casbin)
	authorizer.AddRoleForUser(db, testTenantID, admin.ID, "admin")
	req = httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, _ = app.Test(req)
	assertEqual(t, resp.StatusCode, fiber.StatusOK)
	resp.Body.Close()
}

// =============================================================================
// Policy Reload Test
// =============================================================================

func TestReloadPolicies(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	user := createTestUser(t, db, svc)
	subject := fmt.Sprintf("user:%d", user.ID)

	// Add policy
	authorizer.AddPolicy(db, testTenantID, subject, "/api/reload-test", "GET")

	// Reload policies
	err = authorizer.ReloadPolicies(testTenantID)
	assertNoError(t, err)

	// Verify policy still works
	hasPermission, _ := authorizer.HasPermission(db, testTenantID, user.ID, "/api/reload-test", "GET")
	assertTrue(t, hasPermission, "permission should exist after reload")
}

// =============================================================================
// Add Role Policy Handler Test
// =============================================================================

func TestAddRolePolicyHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	admin := createTestUser(t, db, svc)
	db.Model(admin).Update("role", "admin")
	token := generateTestJWT(t, svc, admin.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/policies/role", auth.RequireRole("admin"), authorizer.AddRolePolicyHandler())

	body := `{"role":"moderator","object":"/api/moderate/*","action":"*"}`
	req := httptest.NewRequest("POST", "/policies/role", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusCreated)

	// Verify role policy was added by checking a user with that role
	testUser := createTestUserWithEmail(t, db, svc, "mod@test.com")
	authorizer.AddRoleForUser(db, testTenantID, testUser.ID, "moderator")

	hasPermission, _ := authorizer.HasPermission(db, testTenantID, testUser.ID, "/api/moderate/post", "DELETE")
	assertTrue(t, hasPermission, "moderator should have permission via role policy")
}

// =============================================================================
// Bulk Policy Handler Test
// =============================================================================

func TestAddBulkPoliciesHandler(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	defer svc.Close()

	authorizer, err := svc.NewAuthorizer(auth.DefaultCasbinConfig())
	assertNoError(t, err)

	admin := createTestUser(t, db, svc)
	db.Model(admin).Update("role", "admin")
	token := generateTestJWT(t, svc, admin.ID, testTenantID)

	app := fiber.New()
	app.Use(svc.TenantMiddleware())
	app.Use(svc.JWTMiddleware())
	app.Post("/policies/bulk", auth.RequireRole("admin"), authorizer.AddBulkPoliciesHandler())

	policies := []map[string]string{
		{"subject": "user:10", "object": "/api/bulk1", "action": "GET"},
		{"subject": "user:10", "object": "/api/bulk2", "action": "POST"},
		{"subject": "user:11", "object": "/api/bulk3", "action": "DELETE"},
	}
	bodyBytes, _ := json.Marshal(map[string]interface{}{"policies": policies})

	req := httptest.NewRequest("POST", "/policies/bulk", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req)
	defer resp.Body.Close()

	assertEqual(t, resp.StatusCode, fiber.StatusCreated)
}
