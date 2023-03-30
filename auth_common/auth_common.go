package auth_common

// Client Types
const (
	CLIENT_TYPE_APP      = "app"
	CLIENT_TYPE_USER     = "user"
	CLIENT_TYPE_BUSINESS = "business"
)

// Client Scopes
const (
	CLIENT_SCOPE_PLATFORM = "platform"
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

	USER_TYPE_PLATFORM = "platform"
	USER_TYPE_APP      = "app"
	USER_TYPE_BUSINESS = "business"
	USER_TYPE_CUSTOMER = "customer"

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
