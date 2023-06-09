package auth_common

import (
	"log"
	"os"
)

// Client Types
const (
	CLIENT_TYPE_APP      = "app"
	CLIENT_TYPE_BUSINESS = "business"
)

// Client Scopes
const (
	CLIENT_SCOPE_PLATFORM   = "platform"
	CLIENT_SCOPE_WEB_APP    = "webapp"
	CLIENT_SCOPE_MOBILE_APP = "mobileapp"
)

// For Auth Verification
const (
	TOKEN_BEARER  = "bearer"
	CLIENT_TYPE   = "client_type"
	CLIENT_SCOPE  = "client_scope"
	GRANT_TYPE    = "grant_type"
	CLIENT_ID     = "client_id"
	CLIENT_SECRET = "client_secret"
	SCOPE         = "scope"
	REFRESH_TOKEN = "refresh_token"

	USER_ID   = "user_id"
	USER_TYPE = "user_type"

	LOGIN_TYPE       = "login_type"
	LOGIN_TYPE_EMAIL = "email"
	LOGIN_TYPE_PHONE = "phone"

	USERNAME = "username"
	PASSWORD = "password"

	GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
	GRANT_TYPE_PASSWORD           = "password"
	GRANT_TYPE_REFRESH            = "refresh"

	// Consts for Token Response
	TYPE_TYPE    = "token_type"
	ACCESS_TOKEN = "access_token"
	EXPIRES_AT   = "expires_at"
	ISSUED_AT    = "issued_at"

	RETURN_TOKEN_TYPE = "Bearer"
)

func GetJwtKey() string {
	jwtKey := os.Getenv("APP_JWT_KEY")
	log.Println("AppCommon::GetJwdKey ", jwtKey)
	return jwtKey
}
