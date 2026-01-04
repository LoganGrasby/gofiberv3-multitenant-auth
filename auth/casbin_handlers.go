package auth

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth/types"
)

// =============================================================================
// Policy Management Handlers
// =============================================================================

// AddPolicyHandler returns a handler for adding a single policy.
func (a *Authorizer) AddPolicyHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.PolicyRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if req.Subject == "" || req.Object == "" || req.Action == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "subject, object, and action are required",
			})
		}

		added, err := a.AddPolicy(db, tenantID, req.Subject, req.Object, req.Action)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to add policy",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"added": added,
			"policy": fiber.Map{
				"subject": req.Subject,
				"domain":  tenantID,
				"object":  req.Object,
				"action":  req.Action,
			},
		})
	}
}

// RemovePolicyHandler returns a handler for removing a single policy.
func (a *Authorizer) RemovePolicyHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.PolicyRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if req.Subject == "" || req.Object == "" || req.Action == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "subject, object, and action are required",
			})
		}

		removed, err := a.RemovePolicy(db, tenantID, req.Subject, req.Object, req.Action)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to remove policy",
			})
		}

		return c.JSON(fiber.Map{
			"removed": removed,
		})
	}
}

// ListPoliciesHandler returns a handler for listing all policies.
func (a *Authorizer) ListPoliciesHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		policies, err := a.GetPolicies(db, tenantID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to list policies",
			})
		}

		// Transform to readable format
		policyList := make([]fiber.Map, 0, len(policies))
		for _, p := range policies {
			if len(p) >= 4 && p[1] == tenantID {
				policyList = append(policyList, fiber.Map{
					"subject": p[0],
					"domain":  p[1],
					"object":  p[2],
					"action":  p[3],
				})
			}
		}

		return c.JSON(fiber.Map{
			"policies": policyList,
			"count":    len(policyList),
		})
	}
}

// AddBulkPoliciesHandler returns a handler for adding multiple policies at once.
func (a *Authorizer) AddBulkPoliciesHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.BulkPolicyRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if len(req.Policies) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "at least one policy is required",
			})
		}

		rules := make([][]string, 0, len(req.Policies))
		for _, p := range req.Policies {
			if p.Subject != "" && p.Object != "" && p.Action != "" {
				rules = append(rules, []string{p.Subject, p.Object, p.Action})
			}
		}

		added, err := a.AddPolicies(db, tenantID, rules)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to add policies",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"added": added,
			"count": len(rules),
		})
	}
}

// =============================================================================
// Role Assignment Handlers
// =============================================================================

// AssignRoleHandler returns a handler for assigning a role to a user.
func (a *Authorizer) AssignRoleHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.RoleRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if req.UserID == 0 || req.Role == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "user_id and role are required",
			})
		}

		// Verify user exists
		var user User
		if err := db.First(&user, req.UserID).Error; err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "user not found",
			})
		}

		added, err := a.AddRoleForUser(db, tenantID, req.UserID, req.Role)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to assign role",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"added":   added,
			"user_id": req.UserID,
			"role":    req.Role,
			"domain":  tenantID,
		})
	}
}

// RemoveRoleHandler returns a handler for removing a role from a user.
func (a *Authorizer) RemoveRoleHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.RoleRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if req.UserID == 0 || req.Role == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "user_id and role are required",
			})
		}

		removed, err := a.RemoveRoleForUser(db, tenantID, req.UserID, req.Role)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to remove role",
			})
		}

		return c.JSON(fiber.Map{
			"removed": removed,
			"user_id": req.UserID,
			"role":    req.Role,
		})
	}
}

// GetUserRolesHandler returns a handler for getting all roles for a user.
func (a *Authorizer) GetUserRolesHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		userID, err := strconv.Atoi(c.Params("id"))
		if err != nil || userID <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid user ID",
			})
		}

		roles, err := a.GetRolesForUser(db, tenantID, uint(userID))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get roles",
			})
		}

		return c.JSON(fiber.Map{
			"user_id": userID,
			"roles":   roles,
		})
	}
}

// GetRoleUsersHandler returns a handler for getting all users with a specific role.
func (a *Authorizer) GetRoleUsersHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		role := c.Params("role")
		if role == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "role parameter is required",
			})
		}

		users, err := a.GetUsersForRole(db, tenantID, role)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get users for role",
			})
		}

		return c.JSON(fiber.Map{
			"role":  role,
			"users": users,
		})
	}
}

// =============================================================================
// Permission Query Handlers
// =============================================================================

// GetUserPermissionsHandler returns a handler for getting all permissions for a user.
func (a *Authorizer) GetUserPermissionsHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		userID, err := strconv.Atoi(c.Params("id"))
		if err != nil || userID <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid user ID",
			})
		}

		permissions, err := a.GetPermissionsForUser(db, tenantID, uint(userID))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get permissions",
			})
		}

		// Transform to readable format
		permList := make([]fiber.Map, 0, len(permissions))
		for _, p := range permissions {
			if len(p) >= 4 {
				permList = append(permList, fiber.Map{
					"subject": p[0],
					"domain":  p[1],
					"object":  p[2],
					"action":  p[3],
				})
			}
		}

		return c.JSON(fiber.Map{
			"user_id":     userID,
			"permissions": permList,
		})
	}
}

// CheckPermissionHandler returns a handler for checking if a user has a specific permission.
func (a *Authorizer) CheckPermissionHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.CheckPermissionRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if req.UserID == 0 || req.Object == "" || req.Action == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "user_id, object, and action are required",
			})
		}

		allowed, err := a.HasPermission(db, tenantID, req.UserID, req.Object, req.Action)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to check permission",
			})
		}

		return c.JSON(fiber.Map{
			"user_id": req.UserID,
			"object":  req.Object,
			"action":  req.Action,
			"allowed": allowed,
		})
	}
}

// GetMyPermissionsHandler returns a handler for getting the current user's permissions.
func (a *Authorizer) GetMyPermissionsHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		permissions, err := a.GetPermissionsForUser(db, tenantID, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get permissions",
			})
		}

		roles, err := a.GetRolesForUser(db, tenantID, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get roles",
			})
		}

		// Transform permissions to readable format
		permList := make([]fiber.Map, 0, len(permissions))
		for _, p := range permissions {
			if len(p) >= 4 {
				permList = append(permList, fiber.Map{
					"subject": p[0],
					"domain":  p[1],
					"object":  p[2],
					"action":  p[3],
				})
			}
		}

		return c.JSON(fiber.Map{
			"user_id":     userID,
			"roles":       roles,
			"permissions": permList,
		})
	}
}

// =============================================================================
// Role Policy Handlers
// =============================================================================

// AddRolePolicyHandler returns a handler for adding a permission to a role.
func (a *Authorizer) AddRolePolicyHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		var req types.RolePolicyRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if req.Role == "" || req.Object == "" || req.Action == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "role, object, and action are required",
			})
		}

		added, err := a.AddPolicyForRole(db, tenantID, req.Role, req.Object, req.Action)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to add role policy",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"added": added,
			"policy": fiber.Map{
				"role":   req.Role,
				"domain": tenantID,
				"object": req.Object,
				"action": req.Action,
			},
		})
	}
}

// =============================================================================
// Admin Handlers
// =============================================================================

// ClearPoliciesHandler returns a handler for clearing all policies (admin only).
func (a *Authorizer) ClearPoliciesHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}
		tenantID := GetTenantID(c)

		if err := a.ClearAllPolicies(db, tenantID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to clear policies",
			})
		}

		return c.JSON(fiber.Map{
			"message": "all policies cleared",
			"domain":  tenantID,
		})
	}
}

// ReloadPoliciesHandler returns a handler for reloading policies from the database.
func (a *Authorizer) ReloadPoliciesHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		tenantID := GetTenantID(c)

		if err := a.casbinManager.ReloadPolicies(tenantID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to reload policies",
			})
		}

		return c.JSON(fiber.Map{
			"message": "policies reloaded",
			"domain":  tenantID,
		})
	}
}
