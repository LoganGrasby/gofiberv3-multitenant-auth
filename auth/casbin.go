package auth

import (
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	fibercasbin "github.com/gofiber/contrib/v3/casbin"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// CasbinConfig holds configuration for Casbin authorization.
type CasbinConfig struct {
	// ModelText is the Casbin model configuration.
	// If empty, uses the default multi-tenant RBAC model.
	ModelText string

	// Unauthorized is called when the user has no valid subject.
	Unauthorized func(fiber.Ctx) error

	// Forbidden is called when the user is authenticated but lacks permission.
	Forbidden func(fiber.Ctx) error
}

// DefaultCasbinConfig returns the default Casbin configuration.
func DefaultCasbinConfig() CasbinConfig {
	return CasbinConfig{
		ModelText: DefaultRBACModel,
		Unauthorized: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		},
		Forbidden: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "permission denied",
			})
		},
	}
}

// DefaultRBACModel is the default multi-tenant RBAC model for Casbin.
// It supports:
// - Domain-based multi-tenancy (dom = tenant_id)
// - Subject (sub = user_id or role)
// - Object (obj = resource path or permission name)
// - Action (act = HTTP method or action name)
// - Role inheritance within domains
// - Wildcard matching using glob patterns (e.g., "blog:*" matches "blog:read")
const DefaultRBACModel = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && globMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`

// SimpleRBACModel is a simpler model without domain support for single-tenant use.
const SimpleRBACModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && globMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`

// CasbinManager manages Casbin enforcers for multiple tenants.
type CasbinManager struct {
	config    CasbinConfig
	enforcers map[string]*casbin.Enforcer
	mu        sync.RWMutex
	model     model.Model
}

// NewCasbinManager creates a new Casbin manager.
func NewCasbinManager(config CasbinConfig) (*CasbinManager, error) {
	if config.ModelText == "" {
		config.ModelText = DefaultRBACModel
	}
	if config.Unauthorized == nil || config.Forbidden == nil {
		defaults := DefaultCasbinConfig()
		if config.Unauthorized == nil {
			config.Unauthorized = defaults.Unauthorized
		}
		if config.Forbidden == nil {
			config.Forbidden = defaults.Forbidden
		}
	}

	// Parse the model once for reuse
	m, err := model.NewModelFromString(config.ModelText)
	if err != nil {
		return nil, fmt.Errorf("failed to parse casbin model: %w", err)
	}

	return &CasbinManager{
		config:    config,
		enforcers: make(map[string]*casbin.Enforcer),
		model:     m,
	}, nil
}

// GetEnforcer returns the Casbin enforcer for a tenant, creating one if needed.
func (cm *CasbinManager) GetEnforcer(db *gorm.DB, tenantID string) (*casbin.Enforcer, error) {
	cm.mu.RLock()
	if e, ok := cm.enforcers[tenantID]; ok {
		cm.mu.RUnlock()
		return e, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double-check after acquiring write lock
	if e, ok := cm.enforcers[tenantID]; ok {
		return e, nil
	}

	// Create adapter for this tenant's database
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin adapter for tenant %s: %w", tenantID, err)
	}

	// Create enforcer with the shared model
	e, err := casbin.NewEnforcer(cm.model, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer for tenant %s: %w", tenantID, err)
	}

	// Enable auto-save for policy changes
	e.EnableAutoSave(true)

	// Load policies from database
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load casbin policies for tenant %s: %w", tenantID, err)
	}

	cm.enforcers[tenantID] = e
	return e, nil
}

// ReloadPolicies reloads policies for a specific tenant.
func (cm *CasbinManager) ReloadPolicies(tenantID string) error {
	cm.mu.RLock()
	e, ok := cm.enforcers[tenantID]
	cm.mu.RUnlock()

	if !ok {
		return nil // No enforcer loaded yet
	}

	return e.LoadPolicy()
}

// ClearEnforcer removes a tenant's enforcer from cache.
func (cm *CasbinManager) ClearEnforcer(tenantID string) {
	cm.mu.Lock()
	delete(cm.enforcers, tenantID)
	cm.mu.Unlock()
}

// ClearAll removes all cached enforcers.
func (cm *CasbinManager) ClearAll() {
	cm.mu.Lock()
	cm.enforcers = make(map[string]*casbin.Enforcer)
	cm.mu.Unlock()
}

// =============================================================================
// Authorization Service Extension
// =============================================================================

// Authorizer provides Casbin-based authorization for the auth service.
type Authorizer struct {
	casbinManager *CasbinManager
	config        CasbinConfig
}

// NewAuthorizer creates a new Casbin-based authorizer.
func (s *Service[U]) NewAuthorizer(config CasbinConfig) (*Authorizer, error) {
	cm, err := NewCasbinManager(config)
	if err != nil {
		return nil, err
	}

	return &Authorizer{
		casbinManager: cm,
		config:        config,
	}, nil
}

// getSubject returns the subject identifier for the current request.
// Uses user ID as the subject, with role-based grouping.
func (a *Authorizer) getSubject(c fiber.Ctx) string {
	userID := GetUserID(c)
	if userID == 0 {
		return ""
	}
	return fmt.Sprintf("user:%d", userID)
}

// getEnforcerFromContext retrieves the enforcer for the current request's tenant.
func (a *Authorizer) getEnforcerFromContext(c fiber.Ctx) (*casbin.Enforcer, error) {
	db := GetTenantDB(c)
	if db == nil {
		return nil, ErrDatabaseNotFound
	}
	tenantID := GetTenantID(c)
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	return a.casbinManager.GetEnforcer(db, tenantID)
}

// ReloadPolicies reloads policies for a specific tenant from the database.
func (a *Authorizer) ReloadPolicies(tenantID string) error {
	return a.casbinManager.ReloadPolicies(tenantID)
}

// ClearEnforcer removes a tenant's enforcer from cache.
func (a *Authorizer) ClearEnforcer(tenantID string) {
	a.casbinManager.ClearEnforcer(tenantID)
}

// =============================================================================
// Middleware Methods
// =============================================================================

// FiberMiddleware returns the underlying Fiber Casbin middleware for a request.
// This is useful for advanced use cases where you need direct access.
func (a *Authorizer) FiberMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		e, err := a.getEnforcerFromContext(c)
		if err != nil {
			return a.config.Unauthorized(c)
		}

		mw := fibercasbin.New(fibercasbin.Config{
			Enforcer: e,
			Lookup: func(c fiber.Ctx) string {
				return a.getSubject(c)
			},
			Unauthorized: a.config.Unauthorized,
			Forbidden:    a.config.Forbidden,
		})

		return mw.RoutePermission()(c)
	}
}

// ValidationRule defines how multiple permissions are validated.
type ValidationRule int

const (
	// MatchAllRule requires all permissions to be satisfied.
	MatchAllRule ValidationRule = iota
	// AtLeastOneRule requires at least one permission to be satisfied.
	AtLeastOneRule
)

// PermissionOption configures permission checking behavior.
type PermissionOption func(*permissionConfig)

type permissionConfig struct {
	validationRule ValidationRule
}

// WithValidationRule sets the validation rule for permission checking.
func WithValidationRule(rule ValidationRule) PermissionOption {
	return func(pc *permissionConfig) {
		pc.validationRule = rule
	}
}

// RequiresPermissions creates middleware that checks if the user has specific permissions.
// Permissions are checked against the tenant's Casbin policies.
//
// Example:
//
//	authz.RequiresPermissions([]string{"blog:create"})
//	authz.RequiresPermissions([]string{"blog:create", "blog:delete"}, casbin.WithValidationRule(casbin.AtLeastOneRule))
func (a *Authorizer) RequiresPermissions(permissions []string, opts ...PermissionOption) fiber.Handler {
	config := &permissionConfig{
		validationRule: MatchAllRule,
	}
	for _, opt := range opts {
		opt(config)
	}

	return func(c fiber.Ctx) error {
		sub := a.getSubject(c)
		if sub == "" {
			return a.config.Unauthorized(c)
		}

		e, err := a.getEnforcerFromContext(c)
		if err != nil {
			return a.config.Unauthorized(c)
		}

		tenantID := GetTenantID(c)

		switch config.validationRule {
		case MatchAllRule:
			for _, perm := range permissions {
				ok, err := e.Enforce(sub, tenantID, perm, "*")
				if err != nil || !ok {
					return a.config.Forbidden(c)
				}
			}
		case AtLeastOneRule:
			hasPermission := false
			for _, perm := range permissions {
				ok, err := e.Enforce(sub, tenantID, perm, "*")
				if err == nil && ok {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				return a.config.Forbidden(c)
			}
		}

		return c.Next()
	}
}

// RoutePermission creates middleware that checks permission based on HTTP method and path.
// The object is derived from the request path and action from the HTTP method.
//
// Example policy:
//
//	p, user:1, tenant1, /api/blog, GET
//	p, admin, tenant1, /api/blog/*, *
func (a *Authorizer) RoutePermission() fiber.Handler {
	return func(c fiber.Ctx) error {
		sub := a.getSubject(c)
		if sub == "" {
			return a.config.Unauthorized(c)
		}

		e, err := a.getEnforcerFromContext(c)
		if err != nil {
			return a.config.Unauthorized(c)
		}

		tenantID := GetTenantID(c)
		obj := c.Path()
		act := c.Method()

		ok, err := e.Enforce(sub, tenantID, obj, act)
		if err != nil || !ok {
			return a.config.Forbidden(c)
		}

		return c.Next()
	}
}

// RequiresRoles creates middleware that checks if the user has any of the specified roles.
// This uses Casbin's grouping policies (g) to check role membership.
//
// Example grouping policy:
//
//	g, user:1, admin, tenant1
//	g, user:2, editor, tenant1
func (a *Authorizer) RequiresRoles(roles []string, opts ...PermissionOption) fiber.Handler {
	config := &permissionConfig{
		validationRule: AtLeastOneRule, // Default to at least one role matching
	}
	for _, opt := range opts {
		opt(config)
	}

	return func(c fiber.Ctx) error {
		sub := a.getSubject(c)
		if sub == "" {
			return a.config.Unauthorized(c)
		}

		e, err := a.getEnforcerFromContext(c)
		if err != nil {
			return a.config.Unauthorized(c)
		}

		tenantID := GetTenantID(c)

		switch config.validationRule {
		case MatchAllRule:
			for _, role := range roles {
				hasRole, err := e.HasRoleForUser(sub, role, tenantID)
				if err != nil || !hasRole {
					return a.config.Forbidden(c)
				}
			}
		case AtLeastOneRule:
			hasAnyRole := false
			for _, role := range roles {
				hasRole, err := e.HasRoleForUser(sub, role, tenantID)
				if err == nil && hasRole {
					hasAnyRole = true
					break
				}
			}
			if !hasAnyRole {
				return a.config.Forbidden(c)
			}
		}

		return c.Next()
	}
}

// =============================================================================
// Policy Management Methods
// =============================================================================

// AddPolicy adds a policy rule for a tenant.
func (a *Authorizer) AddPolicy(db *gorm.DB, tenantID string, sub, obj, act string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	return e.AddPolicy(sub, tenantID, obj, act)
}

// RemovePolicy removes a policy rule for a tenant.
func (a *Authorizer) RemovePolicy(db *gorm.DB, tenantID string, sub, obj, act string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	return e.RemovePolicy(sub, tenantID, obj, act)
}

// GetPolicies returns all policies for a tenant.
func (a *Authorizer) GetPolicies(db *gorm.DB, tenantID string) ([][]string, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return nil, err
	}
	policies, err := e.GetPolicy()
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// GetPoliciesForUser returns all policies for a specific user in a tenant.
func (a *Authorizer) GetPoliciesForUser(db *gorm.DB, tenantID string, userID uint) ([][]string, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return nil, err
	}
	sub := fmt.Sprintf("user:%d", userID)
	policies, err := e.GetFilteredPolicy(0, sub, tenantID)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// AddRoleForUser assigns a role to a user within a tenant.
func (a *Authorizer) AddRoleForUser(db *gorm.DB, tenantID string, userID uint, role string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	sub := fmt.Sprintf("user:%d", userID)
	return e.AddRoleForUser(sub, role, tenantID)
}

// RemoveRoleForUser removes a role from a user within a tenant.
func (a *Authorizer) RemoveRoleForUser(db *gorm.DB, tenantID string, userID uint, role string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	sub := fmt.Sprintf("user:%d", userID)
	return e.DeleteRoleForUser(sub, role, tenantID)
}

// GetRolesForUser returns all roles for a user within a tenant.
func (a *Authorizer) GetRolesForUser(db *gorm.DB, tenantID string, userID uint) ([]string, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return nil, err
	}
	sub := fmt.Sprintf("user:%d", userID)
	return e.GetRolesForUser(sub, tenantID)
}

// GetUsersForRole returns all users with a specific role in a tenant.
func (a *Authorizer) GetUsersForRole(db *gorm.DB, tenantID string, role string) ([]string, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return nil, err
	}
	return e.GetUsersForRole(role, tenantID)
}

// AddPolicyForRole adds a permission policy for a role in a tenant.
func (a *Authorizer) AddPolicyForRole(db *gorm.DB, tenantID string, role, obj, act string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	return e.AddPolicy(role, tenantID, obj, act)
}

// GetPermissionsForUser returns all permissions (direct + role-inherited) for a user.
func (a *Authorizer) GetPermissionsForUser(db *gorm.DB, tenantID string, userID uint) ([][]string, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return nil, err
	}
	sub := fmt.Sprintf("user:%d", userID)
	return e.GetImplicitPermissionsForUser(sub, tenantID)
}

// HasPermission checks if a user has a specific permission.
func (a *Authorizer) HasPermission(db *gorm.DB, tenantID string, userID uint, obj, act string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	sub := fmt.Sprintf("user:%d", userID)
	return e.Enforce(sub, tenantID, obj, act)
}

// =============================================================================
// Bulk Policy Operations
// =============================================================================

// AddPolicies adds multiple policy rules at once.
func (a *Authorizer) AddPolicies(db *gorm.DB, tenantID string, rules [][]string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	// Prepend tenant to each rule
	tenantRules := make([][]string, len(rules))
	for i, rule := range rules {
		if len(rule) >= 3 {
			tenantRules[i] = []string{rule[0], tenantID, rule[1], rule[2]}
		}
	}
	return e.AddPolicies(tenantRules)
}

// RemovePolicies removes multiple policy rules at once.
func (a *Authorizer) RemovePolicies(db *gorm.DB, tenantID string, rules [][]string) (bool, error) {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return false, err
	}
	tenantRules := make([][]string, len(rules))
	for i, rule := range rules {
		if len(rule) >= 3 {
			tenantRules[i] = []string{rule[0], tenantID, rule[1], rule[2]}
		}
	}
	return e.RemovePolicies(tenantRules)
}

// ClearAllPolicies removes all policies for a tenant.
func (a *Authorizer) ClearAllPolicies(db *gorm.DB, tenantID string) error {
	e, err := a.casbinManager.GetEnforcer(db, tenantID)
	if err != nil {
		return err
	}
	// Get all policies for this tenant and remove them
	policies, err := e.GetFilteredPolicy(1, tenantID)
	if err != nil {
		return err
	}
	for _, p := range policies {
		// Convert []string to []interface{}
		args := make([]interface{}, len(p))
		for i, v := range p {
			args[i] = v
		}
		_, _ = e.RemovePolicy(args...)
	}
	// Also clear grouping policies
	groups, err := e.GetFilteredGroupingPolicy(2, tenantID)
	if err != nil {
		return err
	}
	for _, g := range groups {
		// Convert []string to []interface{}
		args := make([]interface{}, len(g))
		for i, v := range g {
			args[i] = v
		}
		_, _ = e.RemoveGroupingPolicy(args...)
	}
	return nil
}
