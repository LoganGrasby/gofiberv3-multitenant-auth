package auth

import (
	"net/url"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

const (
	// SessionKeyOAuthState is the session key for OAuth state parameter.
	SessionKeyOAuthState = "oauth_state"
	// SessionKeyOAuthProvider is the session key for the OAuth provider being used.
	SessionKeyOAuthProvider = "oauth_provider"
)

// OAuthRedirectHandler returns a handler that initiates the OAuth flow.
// It redirects the user to the OAuth provider's authorization page.
// Requires session middleware to be applied.
//
// Usage: GET /auth/{provider}/redirect
// Example: GET /auth/google/redirect
func (s *Service[U]) OAuthRedirectHandler(provider string) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !s.IsOAuthConfigured(provider) {
			return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
				"error": "OAuth provider not configured",
			})
		}

		// Generate state for CSRF protection
		state, err := GenerateSecureToken(32)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to generate state",
			})
		}

		// Store state in session (requires session middleware)
		sess := session.FromContext(c)
		if sess == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "session middleware required for OAuth",
			})
		}

		sess.Set(SessionKeyOAuthState, state)
		sess.Set(SessionKeyOAuthProvider, provider)

		// Get authorization URL
		authURL, err := s.GetOAuthAuthURL(provider, state)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to generate auth URL",
			})
		}

		return c.Redirect().To(authURL)
	}
}

// OAuthCallbackHandler returns a handler that processes the OAuth callback.
// It exchanges the authorization code for tokens and logs in or creates the user.
// Requires session middleware to be applied.
//
// Usage: GET /auth/{provider}/callback
// Example: GET /auth/google/callback?code=xxx&state=yyy
func (s *Service[U]) OAuthCallbackHandler(provider string) fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return s.oauthError(c, "database not available")
		}

		tenantID := GetTenantID(c)

		// Verify state parameter (CSRF protection)
		sess := session.FromContext(c)
		if sess == nil {
			return s.oauthError(c, "session middleware required for OAuth")
		}

		expectedState := sess.Get(SessionKeyOAuthState)
		if expectedState == nil || expectedState.(string) != c.Query("state") {
			return s.oauthError(c, "state mismatch - possible CSRF attack")
		}

		// Clear the state from session
		sess.Delete(SessionKeyOAuthState)
		sess.Delete(SessionKeyOAuthProvider)

		// Check for error from provider
		if errMsg := c.Query("error"); errMsg != "" {
			errDesc := c.Query("error_description")
			if errDesc != "" {
				errMsg = errMsg + ": " + errDesc
			}
			return s.oauthError(c, errMsg)
		}

		// Get authorization code
		code := c.Query("code")
		if code == "" {
			return s.oauthError(c, "authorization code not provided")
		}

		// Exchange code for tokens
		oauthToken, err := s.ExchangeOAuthCode(c.Context(), provider, code)
		if err != nil {
			if s.config.Logger != nil {
				s.config.Logger.Error("OAuth token exchange failed", "provider", provider, "error", err)
			}
			return s.oauthError(c, "token exchange failed")
		}

		// Fetch user profile
		profile, err := s.FetchOAuthProfile(c.Context(), provider, oauthToken)
		if err != nil {
			if s.config.Logger != nil {
				s.config.Logger.Error("OAuth profile fetch failed", "provider", provider, "error", err)
			}
			if err == ErrOAuthEmailNotVerified {
				return s.oauthError(c, "email not verified with provider")
			}
			return s.oauthError(c, "failed to fetch user profile")
		}

		// Perform OAuth login
		result, err := s.OAuthLogin(c.Context(), db, profile, oauthToken, tenantID, c.Get("User-Agent"), c.IP())
		if err != nil {
			if s.config.Logger != nil {
				s.config.Logger.Error("OAuth login failed", "provider", provider, "error", err)
			}

			switch err {
			case ErrOAuthUserCreationDenied:
				return s.oauthError(c, "automatic registration is disabled")
			case ErrOAuthProviderNotLinked:
				return s.oauthError(c, "no account linked to this provider")
			case ErrOAuthProviderAlreadyLinked:
				return s.oauthError(c, "provider already linked to another account")
			case ErrInvalidCredentials:
				return s.oauthError(c, "account is disabled")
			}
			return s.oauthError(c, "login failed")
		}

		if s.config.OnAuthSuccess != nil {
			s.config.OnAuthSuccess(c, "oauth_"+provider, result.User.ID)
		}

		// Set refresh token cookie if cookie settings are configured
		if s.config.CookieHTTPOnly {
			c.Cookie(&fiber.Cookie{
				Name:     "refresh_token",
				Value:    result.Tokens.RefreshToken,
				Expires:  time.Now().Add(s.config.JWTRefreshExpiration),
				HTTPOnly: s.config.CookieHTTPOnly,
				Secure:   s.config.CookieSecure,
				SameSite: s.config.CookieSameSite,
				Domain:   s.config.CookieDomain,
				Path:     "/",
			})
		}

		// Redirect to success URL with tokens
		redirectURL := s.config.OAuthSuccessRedirect
		if redirectURL == "" {
			redirectURL = "/"
		}

		// Parse the redirect URL to add query parameters
		u, err := url.Parse(redirectURL)
		if err != nil {
			u = &url.URL{Path: "/"}
		}

		q := u.Query()
		q.Set("access_token", result.Tokens.AccessToken)
		q.Set("token_type", result.Tokens.TokenType)
		if result.IsNewUser {
			q.Set("new_user", "true")
		}
		u.RawQuery = q.Encode()

		return c.Redirect().To(u.String())
	}
}

// oauthError redirects to the error URL with the error message.
func (s *Service[U]) oauthError(c fiber.Ctx, message string) error {
	redirectURL := s.config.OAuthErrorRedirect
	if redirectURL == "" {
		redirectURL = "/login"
	}

	u, err := url.Parse(redirectURL)
	if err != nil {
		u = &url.URL{Path: "/login"}
	}

	q := u.Query()
	q.Set("error", "oauth_failed")
	q.Set("error_description", message)
	u.RawQuery = q.Encode()

	return c.Redirect().To(u.String())
}

// ListOAuthProvidersHandler returns a handler that lists the OAuth providers linked to the current user.
//
// Usage: GET /auth/providers
// Requires authentication.
func (s *Service[U]) ListOAuthProvidersHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		providers, err := s.GetUserOAuthProviders(c.Context(), db, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to fetch providers",
			})
		}

		// Transform for response (don't expose tokens)
		result := make([]fiber.Map, len(providers))
		for i, p := range providers {
			result[i] = fiber.Map{
				"provider":   p.Provider,
				"email":      p.Email,
				"created_at": p.CreatedAt,
			}
		}

		// Include available providers
		available := []fiber.Map{}
		if s.IsOAuthConfigured("google") {
			available = append(available, fiber.Map{"provider": "google", "name": "Google"})
		}
		if s.IsOAuthConfigured("github") {
			available = append(available, fiber.Map{"provider": "github", "name": "GitHub"})
		}

		return c.JSON(fiber.Map{
			"linked":    result,
			"available": available,
		})
	}
}

// UnlinkOAuthProviderHandler returns a handler that unlinks an OAuth provider from the current user.
//
// Usage: DELETE /auth/providers/:provider
// Example: DELETE /auth/providers/google
// Requires authentication.
func (s *Service[U]) UnlinkOAuthProviderHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		provider := c.Params("provider")
		if provider == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "provider parameter required",
			})
		}

		if err := s.UnlinkOAuthProvider(c.Context(), db, userID, provider); err != nil {
			if ve, ok := err.(*ErrValidation); ok {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": ve.Message,
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to unlink provider",
			})
		}

		return c.JSON(fiber.Map{
			"message": "provider unlinked successfully",
		})
	}
}

// LinkOAuthRedirectHandler returns a handler that initiates OAuth linking for an authenticated user.
// This is used when a user wants to add an additional OAuth provider to their account.
// Requires session middleware and authentication to be applied.
//
// Usage: GET /auth/providers/:provider/link
// Example: GET /auth/providers/github/link
// Requires authentication.
func (s *Service[U]) LinkOAuthRedirectHandler(provider string) fiber.Handler {
	return func(c fiber.Ctx) error {
		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		if !s.IsOAuthConfigured(provider) {
			return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
				"error": "OAuth provider not configured",
			})
		}

		// Generate state for CSRF protection
		state, err := GenerateSecureToken(32)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to generate state",
			})
		}

		// Store state and linking info in session (requires session middleware)
		sess := session.FromContext(c)
		if sess == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "session middleware required for OAuth",
			})
		}

		sess.Set(SessionKeyOAuthState, state)
		sess.Set(SessionKeyOAuthProvider, provider)
		sess.Set("oauth_link_user_id", userID)

		// Get authorization URL
		authURL, err := s.GetOAuthAuthURL(provider, state)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to generate auth URL",
			})
		}

		return c.Redirect().To(authURL)
	}
}

// LinkOAuthCallbackHandler returns a handler that processes the OAuth callback for linking.
// This links the OAuth provider to an existing authenticated user.
// Requires session middleware to be applied.
//
// Usage: GET /auth/providers/:provider/callback
// Example: GET /auth/providers/github/callback?code=xxx&state=yyy
func (s *Service[U]) LinkOAuthCallbackHandler(provider string) fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return s.oauthError(c, "database not available")
		}

		// Verify state parameter (CSRF protection)
		sess := session.FromContext(c)
		if sess == nil {
			return s.oauthError(c, "session middleware required for OAuth")
		}

		expectedState := sess.Get(SessionKeyOAuthState)
		if expectedState == nil || expectedState.(string) != c.Query("state") {
			return s.oauthError(c, "state mismatch - possible CSRF attack")
		}

		// Get the user ID that initiated linking
		linkUserID := sess.Get("oauth_link_user_id")
		if linkUserID == nil {
			return s.oauthError(c, "linking session expired")
		}
		userID := linkUserID.(uint)

		// Clear the session data
		sess.Delete(SessionKeyOAuthState)
		sess.Delete(SessionKeyOAuthProvider)
		sess.Delete("oauth_link_user_id")

		// Check for error from provider
		if errMsg := c.Query("error"); errMsg != "" {
			return s.oauthError(c, errMsg)
		}

		// Get authorization code
		code := c.Query("code")
		if code == "" {
			return s.oauthError(c, "authorization code not provided")
		}

		// Exchange code for tokens
		oauthToken, err := s.ExchangeOAuthCode(c.Context(), provider, code)
		if err != nil {
			return s.oauthError(c, "token exchange failed")
		}

		// Fetch user profile
		profile, err := s.FetchOAuthProfile(c.Context(), provider, oauthToken)
		if err != nil {
			if err == ErrOAuthEmailNotVerified {
				return s.oauthError(c, "email not verified with provider")
			}
			return s.oauthError(c, "failed to fetch user profile")
		}

		// Get the user
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			return s.oauthError(c, "user not found")
		}

		// Link the provider
		if err := s.linkOAuthProvider(c.Context(), db, &user, profile, oauthToken); err != nil {
			if err == ErrOAuthProviderAlreadyLinked {
				return s.oauthError(c, "provider already linked to another account")
			}
			return s.oauthError(c, "failed to link provider")
		}

		// Redirect to success
		redirectURL := s.config.OAuthSuccessRedirect
		if redirectURL == "" {
			redirectURL = "/"
		}

		u, _ := url.Parse(redirectURL)
		q := u.Query()
		q.Set("provider_linked", provider)
		u.RawQuery = q.Encode()

		return c.Redirect().To(u.String())
	}
}
