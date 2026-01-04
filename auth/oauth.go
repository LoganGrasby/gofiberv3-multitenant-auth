package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// OAuthProfile contains user information fetched from an OAuth provider.
type OAuthProfile struct {
	Provider      string `json:"provider"`
	ProviderID    string `json:"provider_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture,omitempty"`
	RawData       string `json:"raw_data,omitempty"` // JSON string of the full provider response
}

// OAuthLoginResult contains the result of an OAuth login.
type OAuthLoginResult struct {
	User      *User      `json:"user"`
	Tokens    *TokenPair `json:"tokens"`
	IsNewUser bool       `json:"is_new_user"`
	LinkedNew bool       `json:"linked_new"` // True if a new provider was linked to existing user
}

// GetOAuthConfig returns the oauth2.Config for the specified provider.
func (s *Service[U]) GetOAuthConfig(provider string) *oauth2.Config {
	switch provider {
	case "google":
		if s.config.GoogleOAuth != nil {
			return s.config.GoogleOAuth.ToOAuth2Config("google")
		}
	case "github":
		if s.config.GitHubOAuth != nil {
			return s.config.GitHubOAuth.ToOAuth2Config("github")
		}
	}
	return nil
}

// IsOAuthConfigured returns true if the specified OAuth provider is configured.
func (s *Service[U]) IsOAuthConfigured(provider string) bool {
	switch provider {
	case "google":
		return s.config.GoogleOAuth.IsConfigured()
	case "github":
		return s.config.GitHubOAuth.IsConfigured()
	}
	return false
}

// GetOAuthAuthURL returns the OAuth authorization URL for the specified provider.
func (s *Service[U]) GetOAuthAuthURL(provider, state string) (string, error) {
	cfg := s.GetOAuthConfig(provider)
	if cfg == nil {
		return "", ErrOAuthNotConfigured
	}
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// ExchangeOAuthCode exchanges an OAuth authorization code for tokens.
func (s *Service[U]) ExchangeOAuthCode(ctx context.Context, provider, code string) (*oauth2.Token, error) {
	cfg := s.GetOAuthConfig(provider)
	if cfg == nil {
		return nil, ErrOAuthNotConfigured
	}

	// Inject custom HTTP client into context for oauth2 library
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.HTTPClient)

	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, NewAuthError("oauth_exchange", err)
	}
	return token, nil
}

// FetchOAuthProfile fetches the user's profile from the OAuth provider.
// FetchOAuthProfile fetches the user's profile from the OAuth provider.
func (s *Service[U]) FetchOAuthProfile(ctx context.Context, provider string, token *oauth2.Token) (*OAuthProfile, error) {
	switch provider {
	case "google":
		return s.fetchGoogleProfile(ctx, token)
	case "github":
		return s.fetchGitHubProfile(ctx, token)
	default:
		return nil, ErrOAuthNotConfigured
	}
}

// OAuthLogin handles the OAuth login flow after receiving the callback.
// It finds or creates a user based on the OAuth profile and returns tokens.
func (s *Service[U]) OAuthLogin(ctx context.Context, db *gorm.DB, profile *OAuthProfile, oauthToken *oauth2.Token, tenantID, userAgent, ipAddress string) (*OAuthLoginResult, error) {
	email := strings.ToLower(strings.TrimSpace(profile.Email))
	if email == "" {
		return nil, &ErrValidation{Field: "email", Message: "email is required from OAuth provider"}
	}

	result := &OAuthLoginResult{}

	// First, check if this OAuth provider+ID is already linked to a user
	var existingProvider OAuthProvider
	err := db.Where("provider = ? AND provider_id = ?", profile.Provider, profile.ProviderID).
		Preload("User").First(&existingProvider).Error

	if err == nil {
		// Provider already linked - log in as that user
		if !existingProvider.User.Active {
			return nil, ErrInvalidCredentials
		}
		result.User = &existingProvider.User

		// Update OAuth tokens
		s.updateOAuthProviderTokens(db, &existingProvider, oauthToken)
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		// Provider not linked yet - check if user exists by email
		var existingUser User
		userErr := db.Where("email = ?", email).First(&existingUser).Error

		if userErr == nil {
			// User exists with this email
			if !existingUser.Active {
				return nil, ErrInvalidCredentials
			}

			if !s.config.OAuthLinkByEmail {
				// Email matching is disabled
				return nil, ErrOAuthProviderNotLinked
			}

			// Link this OAuth provider to the existing user
			if err := s.linkOAuthProvider(ctx, db, &existingUser, profile, oauthToken); err != nil {
				return nil, err
			}

			result.User = &existingUser
			result.LinkedNew = true
		} else if errors.Is(userErr, gorm.ErrRecordNotFound) {
			// No user with this email - create new user if allowed
			if !s.config.OAuthAutoCreateUser {
				return nil, ErrOAuthUserCreationDenied
			}

			// Create new user
			user, err := s.createOAuthUser(ctx, db, profile)
			if err != nil {
				return nil, err
			}

			// Link the OAuth provider
			if err := s.linkOAuthProvider(ctx, db, user, profile, oauthToken); err != nil {
				return nil, err
			}

			result.User = user
			result.IsNewUser = true
			result.LinkedNew = true
		} else {
			return nil, NewAuthError("oauth_login", userErr)
		}
	} else {
		return nil, NewAuthError("oauth_login", err)
	}

	// Generate tokens
	tokens, err := s.generateTokenPairForUser(ctx, db, result.User, tenantID, userAgent, ipAddress)
	if err != nil {
		return nil, err
	}
	result.Tokens = tokens

	// Update last login
	now := time.Now()
	db.Model(result.User).Update("last_login_at", now)

	return result, nil
}

// createOAuthUser creates a new user from an OAuth profile.
func (s *Service[U]) createOAuthUser(ctx context.Context, db *gorm.DB, profile *OAuthProfile) (*User, error) {
	email := strings.ToLower(strings.TrimSpace(profile.Email))

	user := &User{
		Email:        email,
		PasswordHash: "", // No password for OAuth-only users
		Name:         profile.Name,
		Role:         "user",
		Active:       true,
	}

	if err := db.Create(user).Error; err != nil {
		return nil, NewAuthError("create_oauth_user", err)
	}

	return user, nil
}

// linkOAuthProvider links an OAuth provider to a user.
func (s *Service[U]) linkOAuthProvider(ctx context.Context, db *gorm.DB, user *User, profile *OAuthProfile, token *oauth2.Token) error {
	// Check if this provider is already linked to a different user
	var existing OAuthProvider
	err := db.Where("provider = ? AND provider_id = ?", profile.Provider, profile.ProviderID).First(&existing).Error
	if err == nil && existing.UserID != user.ID {
		return ErrOAuthProviderAlreadyLinked
	}

	provider := &OAuthProvider{
		UserID:       user.ID,
		Provider:     profile.Provider,
		ProviderID:   profile.ProviderID,
		Email:        profile.Email,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Metadata:     profile.RawData,
	}

	if !token.Expiry.IsZero() {
		provider.TokenExpiry = &token.Expiry
	}

	return db.Create(provider).Error
}

// updateOAuthProviderTokens updates the OAuth tokens for a provider.
func (s *Service[U]) updateOAuthProviderTokens(db *gorm.DB, provider *OAuthProvider, token *oauth2.Token) {
	updates := map[string]interface{}{
		"access_token": token.AccessToken,
	}
	if token.RefreshToken != "" {
		updates["refresh_token"] = token.RefreshToken
	}
	if !token.Expiry.IsZero() {
		updates["token_expiry"] = token.Expiry
	}
	db.Model(provider).Updates(updates)
}

// GetUserOAuthProviders returns all OAuth providers linked to a user.
func (s *Service[U]) GetUserOAuthProviders(ctx context.Context, db *gorm.DB, userID uint) ([]OAuthProvider, error) {
	var providers []OAuthProvider
	if err := db.Where("user_id = ?", userID).Find(&providers).Error; err != nil {
		return nil, NewAuthError("get_oauth_providers", err)
	}
	return providers, nil
}

// UnlinkOAuthProvider removes an OAuth provider from a user.
// It ensures the user still has at least one way to authenticate.
func (s *Service[U]) UnlinkOAuthProvider(ctx context.Context, db *gorm.DB, userID uint, provider string) error {
	// First, check if user has a password or other providers
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		return ErrUserNotFound
	}

	var providerCount int64
	db.Model(&OAuthProvider{}).Where("user_id = ?", userID).Count(&providerCount)

	// If user has no password and this is their only provider, deny
	if user.PasswordHash == "" && providerCount <= 1 {
		return &ErrValidation{
			Field:   "provider",
			Message: "cannot unlink the only authentication method",
		}
	}

	result := db.Where("user_id = ? AND provider = ?", userID, provider).Delete(&OAuthProvider{})
	if result.Error != nil {
		return NewAuthError("unlink_oauth_provider", result.Error)
	}
	if result.RowsAffected == 0 {
		return &ErrValidation{Field: "provider", Message: "provider not linked"}
	}
	return nil
}

// =============================================================================
// Provider-specific profile fetchers
// =============================================================================

// GoogleUserInfo represents the response from Google's userinfo endpoint.
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

func (s *Service[U]) fetchGoogleProfile(ctx context.Context, token *oauth2.Token) (*OAuthProfile, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, NewAuthError("google_profile", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, NewAuthError("google_profile", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, NewAuthError("google_profile", errors.New(string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewAuthError("google_profile", err)
	}

	var info GoogleUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, NewAuthError("google_profile", err)
	}

	if !info.VerifiedEmail {
		return nil, ErrOAuthEmailNotVerified
	}

	return &OAuthProfile{
		Provider:      "google",
		ProviderID:    info.ID,
		Email:         info.Email,
		EmailVerified: info.VerifiedEmail,
		Name:          info.Name,
		Picture:       info.Picture,
		RawData:       string(body),
	}, nil
}

// GitHubUser represents the response from GitHub's user endpoint.
type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// GitHubEmail represents an email from GitHub's emails endpoint.
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (s *Service[U]) fetchGitHubProfile(ctx context.Context, token *oauth2.Token) (*OAuthProfile, error) {
	// Fetch user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, NewAuthError("github_profile", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, NewAuthError("github_profile", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, NewAuthError("github_profile", errors.New(string(body)))
	}

	userBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewAuthError("github_profile", err)
	}

	var user GitHubUser
	if err := json.Unmarshal(userBody, &user); err != nil {
		return nil, NewAuthError("github_profile", err)
	}

	// GitHub may not include email in the user response if it's private
	// We need to fetch emails separately
	email := user.Email
	emailVerified := false

	if email == "" {
		verifiedEmail, err := s.fetchGitHubPrimaryEmail(ctx, token)
		if err != nil {
			return nil, err
		}
		email = verifiedEmail
		emailVerified = true
	} else {
		// Verify the email is verified
		emailVerified, _ = s.isGitHubEmailVerified(ctx, token, email)
	}

	if !emailVerified {
		return nil, ErrOAuthEmailNotVerified
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	return &OAuthProfile{
		Provider:      "github",
		ProviderID:    fmt.Sprintf("%d", user.ID),
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Picture:       user.AvatarURL,
		RawData:       string(userBody),
	}, nil
}

func (s *Service[U]) fetchGitHubPrimaryEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", NewAuthError("github_emails", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return "", NewAuthError("github_emails", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrOAuthProfileFetch
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewAuthError("github_emails", err)
	}

	var emails []GitHubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", NewAuthError("github_emails", err)
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fallback to any verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", ErrOAuthEmailNotVerified
}

func (s *Service[U]) isGitHubEmailVerified(ctx context.Context, token *oauth2.Token, email string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var emails []GitHubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return false, err
	}

	for _, e := range emails {
		if e.Email == email {
			return e.Verified, nil
		}
	}

	return false, nil
}
