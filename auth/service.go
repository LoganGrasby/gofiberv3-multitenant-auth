package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service is the main authentication service.
type Service struct {
	config       Config
	dbManager    *DatabaseManager
	HTTPClient   *http.Client
	sessionStore fiber.Handler
	authorizer   *Authorizer // cached authorizer instance
}

// New creates a new authentication service.
func New(config Config) (*Service, error) {
	// Apply defaults
	if config.JWTAccessExpiration == 0 {
		config.JWTAccessExpiration = DefaultConfig().JWTAccessExpiration
	}
	if config.JWTRefreshExpiration == 0 {
		config.JWTRefreshExpiration = DefaultConfig().JWTRefreshExpiration
	}
	if config.APIKeyLength == 0 {
		config.APIKeyLength = DefaultConfig().APIKeyLength
	}
	if config.APIKeyPrefix == "" {
		config.APIKeyPrefix = DefaultConfig().APIKeyPrefix
	}
	if config.BcryptCost == 0 {
		config.BcryptCost = DefaultConfig().BcryptCost
	}
	if config.TenantExtractor.Extract == nil {
		config.TenantExtractor = DefaultConfig().TenantExtractor
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create database manager
	dbManager, err := NewDatabaseManager(config)
	if err != nil {
		return nil, err
	}

	// Create session store (internal, memory-only)
	store := session.New(session.Config{
		Storage:        nil, // defaults to memory
		CookieSameSite: config.CookieSameSite,
		CookieSecure:   config.CookieSecure,
		CookieHTTPOnly: config.CookieHTTPOnly,
		CookieDomain:   config.CookieDomain,
	})

	return &Service{
		config:       config,
		dbManager:    dbManager,
		sessionStore: store,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Close releases all resources.
func (s *Service) Close() error {
	return s.dbManager.Close()
}

// Config returns the service configuration (read-only).
func (s *Service) Config() Config {
	return s.config
}

// SetConfig updates the service configuration.
// This is primarily used for testing or dynamic configuration updates.
func (s *Service) SetConfig(config Config) {
	s.config = config
}

// DatabaseManager returns the database manager.
func (s *Service) DatabaseManager() *DatabaseManager {
	return s.dbManager
}

// Authorizer returns the cached Casbin authorizer, creating one if needed.
// This is automatically called by RegisterRoutes when EnableCasbin is true.
// Use this to access the authorizer for custom route middleware.
//
// Example:
//
//	authorizer, err := authService.Authorizer()
//	app.Get("/blog", authorizer.RequiresPermissions([]string{"blog:read"}), handler)
func (s *Service) Authorizer() (*Authorizer, error) {
	if s.authorizer == nil {
		authorizer, err := s.NewAuthorizer(DefaultCasbinConfig())
		if err != nil {
			return nil, err
		}
		s.authorizer = authorizer
	}
	return s.authorizer, nil
}

// SessionMiddleware returns the session middleware handler.
// This should be registered with the Fiber app before any auth routes.
func (s *Service) SessionMiddleware() fiber.Handler {
	return s.sessionStore
}

// =============================================================================
// User Management
// =============================================================================

// RegisterInput contains the data needed to register a new user.
type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// Validate checks the registration input.
func (r *RegisterInput) Validate() error {
	if r.Email == "" {
		return &ErrValidation{Field: "email", Message: "is required"}
	}
	if !IsValidEmail(r.Email) {
		return &ErrValidation{Field: "email", Message: "is invalid"}
	}
	if r.Password == "" {
		return &ErrValidation{Field: "password", Message: "is required"}
	}
	if len(r.Password) < 8 {
		return &ErrValidation{Field: "password", Message: "must be at least 8 characters"}
	}
	return nil
}

// Register creates a new user account.
func (s *Service) Register(ctx context.Context, db *gorm.DB, input RegisterInput) (*User, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}

	// Normalize email
	email := strings.ToLower(strings.TrimSpace(input.Email))

	// Check if user already exists
	var existingUser User
	if err := db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		return nil, ErrUserAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, NewAuthError("register", err)
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(input.Password), s.config.BcryptCost)
	if err != nil {
		return nil, NewAuthError("register", err)
	}

	// Create user
	user := &User{
		Email:        email,
		PasswordHash: string(passwordHash),
		Name:         strings.TrimSpace(input.Name),
		Role:         "user",
		Active:       true,
	}

	if err := db.Create(user).Error; err != nil {
		return nil, NewAuthError("register", err)
	}

	return user, nil
}

// LoginInput contains credentials for login.
type LoginInput struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	UserAgent string `json:"-"`
	IPAddress string `json:"-"`
}

// TokenPair contains access and refresh tokens.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// Login authenticates a user and returns tokens.
func (s *Service) Login(ctx context.Context, db *gorm.DB, input LoginInput, tenantID string) (*TokenPair, *User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))

	// Find user
	var user User
	if err := db.Where("email = ? AND active = ?", email, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, NewAuthError("login", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	// Generate tokens
	tokens, err := s.generateTokenPair(ctx, db, &user, tenantID, input.UserAgent, input.IPAddress)
	if err != nil {
		return nil, nil, err
	}

	// Update last login
	now := time.Now()
	db.Model(&user).Update("last_login_at", now)

	return tokens, &user, nil
}

// RefreshTokens generates new tokens from a refresh token.
func (s *Service) RefreshTokens(ctx context.Context, db *gorm.DB, refreshToken string, tenantID string, userAgent string, ipAddress string) (*TokenPair, error) {
	// Hash the provided token
	tokenHash := HashToken(refreshToken)

	// Find the refresh token
	var rt RefreshToken
	if err := db.Preload("User").Where("token_hash = ?", tokenHash).First(&rt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, NewAuthError("refresh", err)
	}

	// Validate token
	if !rt.IsValid() {
		if rt.Revoked {
			return nil, ErrInvalidRefreshToken
		}
		return nil, ErrInvalidRefreshToken
	}

	// Check user is still active
	if !rt.User.Active {
		return nil, ErrInvalidCredentials
	}

	// Revoke old token
	now := time.Now()
	db.Model(&rt).Updates(map[string]interface{}{
		"revoked":    true,
		"revoked_at": now,
	})

	// Generate new tokens
	return s.generateTokenPair(ctx, db, &rt.User, tenantID, userAgent, ipAddress)
}

// Logout revokes a refresh token.
func (s *Service) Logout(ctx context.Context, db *gorm.DB, refreshToken string) error {
	tokenHash := HashToken(refreshToken)
	now := time.Now()

	result := db.Model(&RefreshToken{}).
		Where("token_hash = ?", tokenHash).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	if result.Error != nil {
		return NewAuthError("logout", result.Error)
	}

	return nil
}

// LogoutAll revokes all refresh tokens for a user.
func (s *Service) LogoutAll(ctx context.Context, db *gorm.DB, userID uint) error {
	now := time.Now()

	result := db.Model(&RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	if result.Error != nil {
		return NewAuthError("logout_all", result.Error)
	}

	return nil
}

// GetUserByID retrieves a user by ID.
func (s *Service) GetUserByID(ctx context.Context, db *gorm.DB, userID uint) (*User, error) {
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, NewAuthError("get_user", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email.
func (s *Service) GetUserByEmail(ctx context.Context, db *gorm.DB, email string) (*User, error) {
	var user User
	if err := db.Where("email = ?", strings.ToLower(email)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, NewAuthError("get_user", err)
	}
	return &user, nil
}

// UpdatePassword changes a user's password.
func (s *Service) UpdatePassword(ctx context.Context, db *gorm.DB, userID uint, oldPassword, newPassword string) error {
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		return ErrUserNotFound
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	// Validate new password
	if len(newPassword) < 8 {
		return ErrPasswordTooWeak
	}

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.config.BcryptCost)
	if err != nil {
		return NewAuthError("update_password", err)
	}

	// Update password
	if err := db.Model(&user).Update("password_hash", string(passwordHash)).Error; err != nil {
		return NewAuthError("update_password", err)
	}

	// Revoke all refresh tokens
	return s.LogoutAll(ctx, db, userID)
}

// =============================================================================
// API Key Management
// =============================================================================

// CreateAPIKeyInput contains data for creating an API key.
type CreateAPIKeyInput struct {
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Description string     `json:"description,omitempty"`
	RateLimit   int        `json:"rate_limit,omitempty"`
}

// CreateAPIKeyOutput contains the created API key details.
type CreateAPIKeyOutput struct {
	APIKey    *APIKey `json:"api_key"`
	RawKey    string  `json:"key"` // Only returned once at creation
	KeyPrefix string  `json:"key_prefix"`
}

// CreateAPIKey creates a new API key for a user.
func (s *Service) CreateAPIKey(ctx context.Context, db *gorm.DB, userID uint, input CreateAPIKeyInput) (*CreateAPIKeyOutput, error) {
	if input.Name == "" {
		return nil, &ErrValidation{Field: "name", Message: "is required"}
	}

	// Generate random key
	rawKey, err := GenerateSecureToken(s.config.APIKeyLength)
	if err != nil {
		return nil, NewAuthError("create_api_key", err)
	}

	// Add prefix
	fullKey := s.config.APIKeyPrefix + rawKey

	// Create prefix for identification (first 8 chars after the prefix)
	keyPrefix := fullKey[:len(s.config.APIKeyPrefix)+8]

	// Hash for storage
	keyHash := HashToken(fullKey)

	// Join scopes
	scopes := strings.Join(input.Scopes, ",")

	apiKey := &APIKey{
		UserID:      userID,
		Name:        input.Name,
		KeyPrefix:   keyPrefix,
		KeyHash:     keyHash,
		Scopes:      scopes,
		ExpiresAt:   input.ExpiresAt,
		Description: input.Description,
		RateLimit:   input.RateLimit,
	}

	if err := db.Create(apiKey).Error; err != nil {
		return nil, NewAuthError("create_api_key", err)
	}

	return &CreateAPIKeyOutput{
		APIKey:    apiKey,
		RawKey:    fullKey,
		KeyPrefix: keyPrefix,
	}, nil
}

// ValidateAPIKey validates an API key and returns the associated user.
func (s *Service) ValidateAPIKey(ctx context.Context, db *gorm.DB, rawKey string) (*APIKey, *User, error) {
	keyHash := HashToken(rawKey)

	var apiKey APIKey
	if err := db.Preload("User").Where("key_hash = ?", keyHash).First(&apiKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrInvalidAPIKey
		}
		return nil, nil, NewAuthError("validate_api_key", err)
	}

	// Check validity
	if apiKey.Revoked {
		return nil, nil, ErrAPIKeyRevoked
	}
	if apiKey.IsExpired() {
		return nil, nil, ErrAPIKeyExpired
	}
	if !apiKey.User.Active {
		return nil, nil, ErrInvalidCredentials
	}

	// Update usage stats
	now := time.Now()
	db.Model(&apiKey).Updates(map[string]interface{}{
		"last_used_at": now,
		"usage_count":  gorm.Expr("usage_count + 1"),
	})

	return &apiKey, &apiKey.User, nil
}

// ListAPIKeys returns all API keys for a user.
func (s *Service) ListAPIKeys(ctx context.Context, db *gorm.DB, userID uint) ([]APIKey, error) {
	var keys []APIKey
	if err := db.Where("user_id = ?", userID).Order("created_at DESC").Find(&keys).Error; err != nil {
		return nil, NewAuthError("list_api_keys", err)
	}
	return keys, nil
}

// GetAPIKey retrieves an API key by ID.
func (s *Service) GetAPIKey(ctx context.Context, db *gorm.DB, keyID uint, userID uint) (*APIKey, error) {
	var key APIKey
	if err := db.Where("id = ? AND user_id = ?", keyID, userID).First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, NewAuthError("get_api_key", err)
	}
	return &key, nil
}

// RevokeAPIKey revokes an API key.
func (s *Service) RevokeAPIKey(ctx context.Context, db *gorm.DB, keyID uint, userID uint) error {
	now := time.Now()
	result := db.Model(&APIKey{}).
		Where("id = ? AND user_id = ?", keyID, userID).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	if result.Error != nil {
		return NewAuthError("revoke_api_key", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// DeleteAPIKey permanently deletes an API key.
func (s *Service) DeleteAPIKey(ctx context.Context, db *gorm.DB, keyID uint, userID uint) error {
	result := db.Where("id = ? AND user_id = ?", keyID, userID).Delete(&APIKey{})
	if result.Error != nil {
		return NewAuthError("delete_api_key", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// =============================================================================
// JWT Token Generation
// =============================================================================

// Claims represents the JWT claims.
type Claims struct {
	jwt.RegisteredClaims
	UserID   uint   `json:"uid"`
	TenantID string `json:"tid"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// generateTokenPair creates a new access/refresh token pair.
func (s *Service) generateTokenPair(ctx context.Context, db *gorm.DB, user *User, tenantID string, userAgent string, ipAddress string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(s.config.JWTAccessExpiration)

	// Create access token claims
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   fmt.Sprintf("%d", user.ID),
		},
		UserID:   user.ID,
		TenantID: tenantID,
		Email:    user.Email,
		Role:     user.Role,
	}

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessTokenString, err := accessToken.SignedString(s.config.JWTSecret)
	if err != nil {
		return nil, NewAuthError("generate_tokens", err)
	}

	// Generate refresh token
	refreshTokenRaw, err := GenerateSecureToken(32)
	if err != nil {
		return nil, NewAuthError("generate_tokens", err)
	}

	// Store refresh token
	refreshExpiry := now.Add(s.config.JWTRefreshExpiration)
	rt := &RefreshToken{
		UserID:    user.ID,
		TokenHash: HashToken(refreshTokenRaw),
		ExpiresAt: refreshExpiry,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	if err := db.Create(rt).Error; err != nil {
		return nil, NewAuthError("generate_tokens", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenRaw,
		ExpiresAt:    accessExpiry,
		TokenType:    "Bearer",
	}, nil
}

// ValidateAccessToken validates a JWT access token and returns the claims.
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.JWTSecret, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
