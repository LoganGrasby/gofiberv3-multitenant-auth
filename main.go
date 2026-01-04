package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

// =============================================================================
// Custom User Model Example
// =============================================================================
// CustomUser demonstrates how to extend the base user model with
// application-specific fields. Embed auth.BaseUser to inherit all
// authentication functionality.
type CustomUser struct {
	auth.BaseUser
	OrganizationID uint   `json:"organization_id" gorm:"index"`
	Department     string `json:"department"`
	EmployeeID     string `json:"employee_id" gorm:"uniqueIndex"`
}

// TableName ensures GORM uses the correct table name
func (CustomUser) TableName() string {
	return "users"
}

func main() {
	// ==========================================================================
	// Option A: Default User Model (simplest)
	// ==========================================================================
	// authService, err := auth.New(auth.Config{...})
	//
	// ==========================================================================
	// Option B: Custom User Model (shown below)
	// ==========================================================================
	// Use NewWithModel[T] to specify your custom user type.
	// The custom model is automatically migrated to the database.

	authService, err := auth.NewWithModel[*CustomUser](auth.Config{
		DatabaseDir:         "./data/tenants",
		JWTSecret:           []byte("your-super-secret-key-min-32-chars!!"),
		JWTAccessExpiration: 15 * time.Minute,
		TenantExtractor:     extractors.FromHeader("X-Tenant-ID"),
		CookieSecure:        false, // Set to true in production with HTTPS
		CookieHTTPOnly:      true,
		AllowTenantCreation: true,
		GoogleOAuth: &auth.OAuthProviderConfig{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  "http://localhost:3000/api/auth/google/callback",
		},
		GitHubOAuth: &auth.OAuthProviderConfig{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURL:  "http://localhost:3000/api/auth/github/callback",
			Scopes:       []string{"user:email", "read:user"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}
	defer authService.Close()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": err.Error(),
			})
		},
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowCredentials: true,
	}))

	// Health check (no tenant required)
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Serve static index.html
	app.Get("/", func(c fiber.Ctx) error {
		return c.SendFile("./index.html")
	})

	// ==========================================================================
	// Register all auth routes with one line!
	// ==========================================================================
	// This registers:
	// - POST /api/auth/register, /api/auth/login, /api/auth/refresh, /api/auth/logout
	// - GET  /api/auth/:provider/redirect, /api/auth/:provider/callback (OAuth)
	// - GET  /api/me, POST /api/auth/logout-all, /api/auth/change-password
	// - POST /api/api-keys, GET /api/api-keys, etc. (API key management)
	// - GET  /api/permissions/me, POST /api/permissions/check
	// - All Casbin policy/role management routes under /api/policies and /api/roles
	authService.RegisterRoutes(app, auth.RouterConfig{
		Prefix:       "/api",
		EnableCasbin: true, // Authorizer created automatically
	})

	// ==========================================================================
	// Example: Custom routes using handler groups
	// ==========================================================================
	// You can also register routes manually using handler groups for more control:
	//
	//   authHandlers := authService.Auth()
	//   app.Post("/custom/login", authHandlers.Login())
	//
	//   oauthHandlers := authService.OAuth()
	//   app.Get("/sso/google", oauthHandlers.Redirect("google"))
	//
	//   authorizer, _ := authService.Authorizer()
	//   casbinHandlers := authorizer.Handlers()
	//   app.Get("/perms", casbinHandlers.GetMyPermissions())

	// ==========================================================================
	// Example: Protected routes with Casbin permission checks
	// ==========================================================================
	// Get the authorizer for custom middleware (auto-created by RegisterRoutes)
	authorizer, _ := authService.Authorizer()

	api := app.Group("/api", authService.TenantMiddleware())
	protected := api.Group("", authService.AuthMiddleware())

	// Example: Route permission based on HTTP method + path
	// Requires policy like: p, user:1, tenant1, /api/blog, GET
	protected.Get("/blog",
		authorizer.RoutePermission(),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "blog list",
				"tenant":  auth.GetTenantID(c),
			})
		},
	)

	// Example: Custom permission check (requires "blog:create" permission)
	// Requires policy like: p, user:1, tenant1, blog:create, *
	protected.Post("/blog",
		authorizer.RequiresPermissions([]string{"blog:create"}),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "blog created",
			})
		},
	)

	// Example: Multiple permissions with MatchAllRule (must have ALL permissions)
	protected.Delete("/blog/:id",
		authorizer.RequiresPermissions(
			[]string{"blog:read", "blog:delete"},
			auth.WithValidationRule(auth.MatchAllRule),
		),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "blog deleted",
				"id":      c.Params("id"),
			})
		},
	)

	// Example: Role-based access with Casbin
	// Requires grouping policy like: g, user:1, editor, tenant1
	protected.Get("/editor/dashboard",
		authorizer.RequiresRoles([]string{"editor", "admin"}),
		func(c fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "editor dashboard",
				"tenant":  auth.GetTenantID(c),
			})
		},
	)

	// Example: Simple role check (without Casbin)
	protected.Get("/admin/stats", auth.RequireRole("admin"), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "admin stats",
			"tenant":  auth.GetTenantID(c),
		})
	})

	// Example: Scope requirement (for API keys)
	protected.Get("/reports", auth.RequireScope("reports:read"), func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "reports data",
		})
	})

	// Example: Custom endpoint using the database directly
	protected.Get("/users", func(c fiber.Ctx) error {
		db := auth.GetTenantDB(c)
		if db == nil {
			return c.Status(500).JSON(fiber.Map{"error": "database not available"})
		}

		// Query custom user model with all fields (including custom ones)
		var users []CustomUser
		if err := db.Select("id", "email", "name", "role", "organization_id", "department", "employee_id", "created_at").Find(&users).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "failed to fetch users"})
		}

		return c.JSON(fiber.Map{"users": users})
	})

	// ==========================================================================
	// Example: Accessing custom user fields in handlers
	// ==========================================================================
	protected.Get("/profile", func(c fiber.Ctx) error {
		// GetUserAs[T] returns your custom user type with all fields
		user := auth.GetUserAs[*CustomUser](c)
		if user == nil {
			return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
		}

		// Access both inherited (BaseUser) and custom fields
		return c.JSON(fiber.Map{
			// Inherited fields via interface methods
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"name":  user.GetName(),
			"role":  user.GetRole(),
			// Custom fields accessed directly
			"organization_id": user.OrganizationID,
			"department":      user.Department,
			"employee_id":     user.EmployeeID,
		})
	})

	// Alternative: Use GetUserModel for interface-only access (works with any user type)
	protected.Get("/me/summary", func(c fiber.Ctx) error {
		user := auth.GetUserModel(c)
		if user == nil {
			return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
		}

		return c.JSON(fiber.Map{
			"id":    user.GetID(),
			"email": user.GetEmail(),
			"role":  user.GetRole(),
		})
	})

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down...")
		if err := app.Shutdown(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}()

	// Start server
	log.Println("Starting server on :3000")
	log.Println("Using CustomUser model with OrganizationID, Department, EmployeeID fields")
	log.Println("Auth routes registered via RegisterRoutes()")
	log.Println("Casbin authorization enabled for fine-grained permission control")
	if err := app.Listen(":3000"); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
