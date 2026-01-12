package handlers

import (
	"github.com/gofiber/fiber/v3"
)

// CasbinHandlers groups Casbin authorization HTTP handlers.
// Use authorizer.Handlers() to obtain an instance.
type CasbinHandlers struct {
	authorizer interface{}
}

// NewCasbinHandlers creates a new CasbinHandlers instance.
func NewCasbinHandlers(authorizer interface{}) *CasbinHandlers {
	return &CasbinHandlers{authorizer: authorizer}
}

// casbinHandlerProvider defines the Casbin handler methods we need.
type casbinHandlerProvider interface {
	AddPolicyHandler() fiber.Handler
	RemovePolicyHandler() fiber.Handler
	ListPoliciesHandler() fiber.Handler
	AddBulkPoliciesHandler() fiber.Handler
	ClearPoliciesHandler() fiber.Handler
	ReloadPoliciesHandler() fiber.Handler
	AssignRoleHandler() fiber.Handler
	RemoveRoleHandler() fiber.Handler
	GetUserRolesHandler() fiber.Handler
	GetRoleUsersHandler() fiber.Handler
	GetUserPermissionsHandler() fiber.Handler
	CheckPermissionHandler() fiber.Handler
	GetMyPermissionsHandler() fiber.Handler
	AddRolePolicyHandler() fiber.Handler
}

// =============================================================================
// Policy Management
// =============================================================================

// AddPolicy returns a handler for adding a single policy.
// Requires admin role.
//
// POST /policies
//
// Request body: types.PolicyRequest
// Response: { "added": bool, "policy": {...} }
func (h *CasbinHandlers) AddPolicy() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.AddPolicyHandler()
	}
	return casbinErrorHandler("add policy not available")
}

// RemovePolicy returns a handler for removing a single policy.
// Requires admin role.
//
// DELETE /policies
//
// Request body: types.PolicyRequest
// Response: { "removed": bool }
func (h *CasbinHandlers) RemovePolicy() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.RemovePolicyHandler()
	}
	return casbinErrorHandler("remove policy not available")
}

// ListPolicies returns a handler for listing all policies.
// Requires admin role.
//
// GET /policies
//
// Response: { "policies": [...], "count": int }
func (h *CasbinHandlers) ListPolicies() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.ListPoliciesHandler()
	}
	return casbinErrorHandler("list policies not available")
}

// AddBulkPolicies returns a handler for adding multiple policies at once.
// Requires admin role.
//
// POST /policies/bulk
//
// Request body: types.BulkPolicyRequest
// Response: { "added": bool, "count": int }
func (h *CasbinHandlers) AddBulkPolicies() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.AddBulkPoliciesHandler()
	}
	return casbinErrorHandler("add bulk policies not available")
}

// ClearPolicies returns a handler for clearing all policies.
// Requires admin role.
//
// DELETE /policies/clear
//
// Response: { "message": "all policies cleared", "domain": "..." }
func (h *CasbinHandlers) ClearPolicies() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.ClearPoliciesHandler()
	}
	return casbinErrorHandler("clear policies not available")
}

// ReloadPolicies returns a handler for reloading policies from the database.
// Requires admin role.
//
// POST /policies/reload
//
// Response: { "message": "policies reloaded", "domain": "..." }
func (h *CasbinHandlers) ReloadPolicies() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.ReloadPoliciesHandler()
	}
	return casbinErrorHandler("reload policies not available")
}

// =============================================================================
// Role Management
// =============================================================================

// AssignRole returns a handler for assigning a role to a user.
// Requires admin role.
//
// POST /roles/assign
//
// Request body: types.RoleRequest
// Response: { "added": bool, "user_id": int, "role": "...", "domain": "..." }
func (h *CasbinHandlers) AssignRole() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.AssignRoleHandler()
	}
	return casbinErrorHandler("assign role not available")
}

// RemoveRole returns a handler for removing a role from a user.
// Requires admin role.
//
// POST /roles/remove
//
// Request body: types.RoleRequest
// Response: { "removed": bool, "user_id": int, "role": "..." }
func (h *CasbinHandlers) RemoveRole() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.RemoveRoleHandler()
	}
	return casbinErrorHandler("remove role not available")
}

// GetUserRoles returns a handler for getting all roles for a user.
// Requires admin role.
//
// GET /roles/user/:id
//
// Response: { "user_id": int, "roles": [...] }
func (h *CasbinHandlers) GetUserRoles() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.GetUserRolesHandler()
	}
	return casbinErrorHandler("get user roles not available")
}

// GetRoleUsers returns a handler for getting all users with a specific role.
// Requires admin role.
//
// GET /roles/:role/users
//
// Response: { "role": "...", "users": [...] }
func (h *CasbinHandlers) GetRoleUsers() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.GetRoleUsersHandler()
	}
	return casbinErrorHandler("get role users not available")
}

// =============================================================================
// Permission Queries
// =============================================================================

// GetUserPermissions returns a handler for getting all permissions for a user.
// Requires admin role.
//
// GET /roles/user/:id/permissions
//
// Response: { "user_id": int, "permissions": [...] }
func (h *CasbinHandlers) GetUserPermissions() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.GetUserPermissionsHandler()
	}
	return casbinErrorHandler("get user permissions not available")
}

// CheckPermission returns a handler for checking if a user has a specific permission.
// Requires authentication.
//
// POST /permissions/check
//
// Request body: types.CheckPermissionRequest
// Response: { "user_id": int, "object": "...", "action": "...", "allowed": bool }
func (h *CasbinHandlers) CheckPermission() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.CheckPermissionHandler()
	}
	return casbinErrorHandler("check permission not available")
}

// GetMyPermissions returns a handler for getting the current user's permissions.
// Requires authentication.
//
// GET /permissions/me
//
// Response: { "user_id": int, "roles": [...], "permissions": [...] }
func (h *CasbinHandlers) GetMyPermissions() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.GetMyPermissionsHandler()
	}
	return casbinErrorHandler("get my permissions not available")
}

// =============================================================================
// Role Policies
// =============================================================================

// AddRolePolicy returns a handler for adding a permission to a role.
// Requires admin role.
//
// POST /policies/role
//
// Request body: types.RolePolicyRequest
// Response: { "added": bool, "policy": {...} }
func (h *CasbinHandlers) AddRolePolicy() fiber.Handler {
	if hp, ok := h.authorizer.(casbinHandlerProvider); ok {
		return hp.AddRolePolicyHandler()
	}
	return casbinErrorHandler("add role policy not available")
}

func casbinErrorHandler(message string) fiber.Handler {
	return func(c fiber.Ctx) error {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": message,
		})
	}
}
