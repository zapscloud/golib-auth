package auth_services

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	fiber_utils "github.com/gofiber/utils"
	"github.com/golang-jwt/jwt/v4"
	"github.com/zapscloud/golib-auth/auth_common"
	"github.com/zapscloud/golib-platform/platform_common"
	"github.com/zapscloud/golib-platform/platform_services"
	"github.com/zapscloud/golib-utils/utils"
)

const TOKEN_EXPIRY_DAYS = (7 * 24 * time.Hour) // 7 * 24 hours = 168 hours

type Claims struct {
	ClientType  string `json:"client_type"`
	ClientScope string `json:"client_scope"`
	ClientId    string `json:"client_id"`
	GrandType   string `json:"grant_type"`
	BusinessId  string `json:"business_id,omitempty"`
	UserId      string `json:"user_id,omitempty"`
	TokenString string `json:"token_string,omitempty"`

	jwt.RegisteredClaims
}

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.Lmicroseconds)
}

func AuthValidate(ctx *fiber.Ctx) (Claims, error) { // for validation process
	//  validation process Start
	claims := Claims{}
	err := ValidateBearerAuth(ctx, &claims)
	if err != nil {
		fmt.Println("err for final ", err)
		return claims, err
	}
	fmt.Println("auth", claims)

	return claims, nil
}

func GetBasicAuth(ctx *fiber.Ctx) (string, string, error) {
	// Get authorization header
	authstring := ctx.Get(fiber.HeaderAuthorization)

	// Check if the header contains content besides "basic".
	if len(authstring) <= 6 || strings.ToLower(authstring[:5]) != "basic" {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Bad Request Header", ErrorDetail: "Missing Authorization Header"}
		return "", "", err
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(authstring[6:])
	if err != nil {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Bad Request Header", ErrorDetail: "Missing Authorization Header"}
		return "", "", err
	}

	// Get the credentials
	creds := fiber_utils.UnsafeString(raw)

	// Check if the credentials are in the correct form
	// which is "username:password".
	index := strings.Index(creds, ":")
	if index == -1 {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Bad Request Header", ErrorDetail: "Missing Authorization Header"}
		return "", "", err
	}

	// Get the username and password
	authkey := creds[:index]
	authsecret := creds[index+1:]

	log.Println("Auth String ", authstring)
	return authkey, authsecret, err

}

func GetScope(dataAuth utils.Map) utils.Map {
	mapScopes := utils.Map{}
	if scopeValue, scopeOk := dataAuth[auth_common.SCOPE]; scopeOk && scopeValue.(string) != "" {
		mapScopes = parseScope(scopeValue.(string))
	}
	log.Println("Scopes ", mapScopes)

	return mapScopes
}

func ValidateInputParams(ctx *fiber.Ctx) (utils.Map, error) {

	dataAuth := utils.Map{
		auth_common.GRANT_TYPE:    ctx.FormValue(auth_common.GRANT_TYPE, ""),
		auth_common.CLIENT_ID:     ctx.FormValue(auth_common.CLIENT_ID, ""),
		auth_common.CLIENT_SECRET: ctx.FormValue(auth_common.CLIENT_SECRET, ""),
		auth_common.USERNAME:      ctx.FormValue(auth_common.USERNAME, ""),
		auth_common.PASSWORD:      ctx.FormValue(auth_common.PASSWORD, ""),
		auth_common.REFRESH_TOKEN: ctx.FormValue(auth_common.REFRESH_TOKEN, ""),
		auth_common.SCOPE:         ctx.FormValue(auth_common.SCOPE, ""),
	}

	// verify auth credentials
	clientId, clientSecret, err := GetBasicAuth(ctx)
	if err == nil {
		dataAuth[auth_common.CLIENT_ID] = clientId
		dataAuth[auth_common.CLIENT_SECRET] = clientSecret
	}

	log.Println("ValidateInputParams : ", dataAuth)

	// Validate Grant Type
	grantType := dataAuth[auth_common.GRANT_TYPE].(string)

	if grantType != auth_common.GRANT_TYPE_CLIENT_CREDENTIALS &&
		grantType != auth_common.GRANT_TYPE_PASSWORD &&
		grantType != auth_common.GRANT_TYPE_REFRESH {
		err := &utils.AppError{ErrorStatus: 400, ErrorMsg: "Bad Request", ErrorDetail: "Invalid Grant Type : [" + grantType + "]"}
		return nil, err

	}

	if utils.IsEmpty(dataAuth[auth_common.CLIENT_ID].(string)) || utils.IsEmpty(dataAuth[auth_common.CLIENT_SECRET].(string)) {
		err := &utils.AppError{ErrorStatus: 400, ErrorMsg: "Bad Request", ErrorDetail: "Missing Client Credentials"}
		return nil, err
	}

	if grantType == auth_common.GRANT_TYPE_PASSWORD {
		if utils.IsEmpty(dataAuth[auth_common.USERNAME].(string)) {
			err := &utils.AppError{ErrorStatus: 400, ErrorMsg: "Bad Request", ErrorDetail: "Missing User Name"}
			return nil, err
		}

		if utils.IsEmpty(dataAuth[auth_common.PASSWORD].(string)) {
			err := &utils.AppError{ErrorStatus: 400, ErrorMsg: "Bad Request", ErrorDetail: "Missing User Password"}
			return nil, err
		}

	} else if grantType == auth_common.GRANT_TYPE_REFRESH {
		if utils.IsEmpty(dataAuth[auth_common.REFRESH_TOKEN].(string)) {
			err := &utils.AppError{ErrorStatus: 400, ErrorMsg: "Bad Request", ErrorDetail: "Missing User Name"}
			return nil, err
		}
	}

	return dataAuth, nil
}

func GetAuthToken(authClaims Claims) Claims {
	log.Println("GetAuthToken::Auth token claims ", authClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims)
	tokenString, err := token.SignedString([]byte(auth_common.GetJwtKey()))
	if err != nil {
		log.Println("Error in SignedString:", err)
	}
	log.Println("GetAuthToken::Token String ", tokenString)

	authClaims.TokenString = tokenString
	authClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(TOKEN_EXPIRY_DAYS))
	authClaims.IssuedAt = jwt.NewNumericDate(time.Now())

	return authClaims
}

func GetRefreshToken(ctx *fiber.Ctx) (Claims, error) {

	claims, err := AuthValidate(ctx)
	log.Println("GetRefreshToken::Auth token claims ", claims)
	if err != nil {
		return Claims{}, err
	}
	if claims.GrandType != auth_common.GRANT_TYPE_PASSWORD {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Access Denied", ErrorDetail: "Invalid Grant Type. Password Grant Only Allowed to Refresh the Token."}
		return Claims{}, err
	}

	// Get NewToken
	claims = GetAuthToken(claims)

	return claims, nil
}

/**************************************************************************************
**
** ValidateAuthCredentials:
**
**
**
***************************************************************************************/
func ValidateAuthCredential(dbProps utils.Map, dataAuth utils.Map) (utils.Map, error) {

	log.Printf("ValidateAppAuth %v", dataAuth)

	// Authenticate with Clients tables
	clientType, clientScope, clientData, err := AuthenticateClient(dbProps, dataAuth)
	if err != nil {
		return nil, err
	}

	log.Println("Auth Client Record ", clientData, err)

	// Update Client Data in AuthData
	dataAuth[platform_common.FLD_CLIENT_TYPE] = clientData[platform_common.FLD_CLIENT_TYPE].(string)
	dataAuth[platform_common.FLD_CLIENT_SCOPE] = clientData[platform_common.FLD_CLIENT_SCOPE].(string)

	// Get the GrantType
	grantType := dataAuth[auth_common.GRANT_TYPE].(string)

	// Get Scope values if anything passed
	mapScopes := GetScope(dataAuth)

	switch grantType {
	//
	// ============[ Grant_Type: Client Credentials ] ========================================
	case auth_common.GRANT_TYPE_CLIENT_CREDENTIALS:
		/* All validation done already, nothing todo further so just return the result. */

	//
	// ============[ Grant_Type: Password Credentials ] ======================================
	case auth_common.GRANT_TYPE_PASSWORD:

		var businessId string = ""
		// Obtain BusinessId value

		switch clientType {
		case auth_common.CLIENT_TYPE_APP:
			if clientScope == auth_common.CLIENT_SCOPE_PLATFORM {
				// BusinessId not needed so skip it
			} else {
				// For all other cases like WebApp, MobileApp and etc
				businessId, err = utils.GetMemberDataStr(mapScopes, platform_common.FLD_BUSINESS_ID)
				if err != nil {
					return nil, err
				}
			}
		case auth_common.CLIENT_TYPE_BUSINESS:
			// ClientScope will be considered as BusinessId
			businessId = clientScope // Take clientScope as businessId
		}

		// Validate BusinessId is exist
		if !utils.IsEmpty(businessId) {
			_, err = authenticateBussiness(dbProps, businessId)
			if err != nil {
				return nil, err
			}
		}

		// Assign BusinessId in AuthData
		dataAuth[platform_common.FLD_BUSINESS_ID] = businessId

		// Check the scope->client_scope
		if clientScope == auth_common.CLIENT_SCOPE_PLATFORM {
			// ****** Validate the Password credentials with "sysUser" Table ******

			// Authenticate SysUser
			sysUserData, err := authenticateSysUser(dbProps, dataAuth)
			if err != nil {
				return utils.Map{}, err
			}

			dataAuth[platform_common.FLD_SYS_USER_ID] = sysUserData[platform_common.FLD_SYS_USER_ID].(string)
		} else {
			// ****** Validate the Password credentials with "appUser" Table ******

			// Authenticate AppUser
			sysUserData, err := authenticateAppUser(dbProps, dataAuth)
			if err != nil {
				return utils.Map{}, err
			}

			dataAuth[platform_common.FLD_APP_USER_ID] = sysUserData[platform_common.FLD_APP_USER_ID].(string)
		}
	//
	// ============[ Grant_Type: REFRESH ] ========================================
	case auth_common.GRANT_TYPE_REFRESH:
		/* Need to Implement Refersh Token */
		//dataAuth.RefreshToken = ctx.FormValue("refresh_token")
	}

	log.Printf("Auth Values %v", dataAuth)
	return dataAuth, nil
}

func AuthenticateClient(dbProps utils.Map, dataAuth utils.Map) (string, string, utils.Map, error) {
	clientId := dataAuth[auth_common.CLIENT_ID].(string)
	clientSecret := dataAuth[auth_common.CLIENT_SECRET].(string)

	// Get Scope values if anything passed
	mapScopes := GetScope(dataAuth)

	// Obtain ClientType value
	clientType, err := utils.GetMemberDataStr(mapScopes, auth_common.CLIENT_TYPE)
	if err != nil {
		return "", "", nil, err
	}
	// obtain ClientScope value
	clientScope, err := utils.GetMemberDataStr(mapScopes, auth_common.CLIENT_SCOPE)
	if err != nil {
		return "", "", nil, err
	}

	// Create Service Instance
	clientService, err := platform_services.NewClientsService(dbProps)
	if err != nil {
		log.Println("Client DB Error ", err)
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Client DB Connection Error", ErrorDetail: "Client DB Connection Error"}
		return "", "", nil, err
	}
	defer clientService.EndService()

	log.Println("authenticateAppClient ", clientId, clientSecret, clientType, clientScope)

	clientData, err := clientService.Authenticate(clientId, clientSecret, clientType, clientScope)
	if err != nil {
		log.Println("Auth DB Error ", err)
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Invalid Access", ErrorDetail: "Authentication Failure"}
		return "", "", nil, err
	}

	return clientType, clientScope, clientData, err
}

func Map2Claims(authData utils.Map) Claims {
	var authClaims Claims

	authClaims.ClientId = authData[auth_common.CLIENT_ID].(string)
	authClaims.GrandType = authData[auth_common.GRANT_TYPE].(string)

	if dataval, dataok := authData[platform_common.FLD_CLIENT_TYPE]; dataok {
		authClaims.ClientType = dataval.(string)
	}

	if dataval, dataok := authData[platform_common.FLD_CLIENT_SCOPE]; dataok {
		authClaims.ClientScope = dataval.(string)
	}

	if dataval, dataok := authData[platform_common.FLD_BUSINESS_ID]; dataok {
		authClaims.BusinessId = dataval.(string)
	}

	if dataval, dataok := authData[platform_common.FLD_APP_USER_ID]; dataok {
		authClaims.UserId = dataval.(string)
	}

	return authClaims
}
