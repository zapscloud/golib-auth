package auth_services

import (
	"encoding/base64"
	"log"
	"strings"
	"time"

	fiber_utils "github.com/gofiber/utils"
	"github.com/golang-jwt/jwt/v4"
	"github.com/zapscloud/golib-auth/auth_common"
	"github.com/zapscloud/golib-platform-repository/platform_common"
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

func getBasicAuth(authString string) (string, string, error) {

	// Check if the header contains content besides "basic".
	if len(authString) <= 6 || strings.ToLower(authString[:5]) != "basic" {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Bad Request Header", ErrorDetail: "Missing Authorization Header"}
		return "", "", err
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(authString[6:])
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

	log.Println("getBasicAuth::Auth String ", authString)
	return authkey, authsecret, err
}

func validateAuthData(dataAuth utils.Map) (utils.Map, error) {
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

/**************************************************************************************
**
** ValidateAuthCredentials:
**
**
**
***************************************************************************************/
func ValidateAuthCredential(dbProps utils.Map, dataAuth utils.Map, calledFromPlatformController bool) (utils.Map, error) {

	log.Printf("ValidateAppAuth %v", dataAuth)

	// Authenticate with Clients tables
	clientData, err := authenticateClient(dbProps, dataAuth)
	if err != nil {
		return nil, err
	}
	log.Println("Auth Client Record ", clientData, err)

	// Get clientType and clientScope from the clientData
	clientType := clientData[platform_common.FLD_CLIENT_TYPE].(string)
	clientScope := clientData[platform_common.FLD_CLIENT_SCOPE].(string)

	if !calledFromPlatformController {
		// Validate BusinessId
		businessId, err := validateBusinessId(clientType, clientScope, dataAuth)
		if err != nil {
			return nil, err
		}

		// Validate BusinessId is exist
		if !utils.IsEmpty(businessId) {
			_, err = isBusinessExist(dbProps, businessId)
			if err != nil {
				return nil, err
			}

			// Assign BusinessId in AuthData
			dataAuth[platform_common.FLD_BUSINESS_ID] = businessId
		}
	}

	// Get the GrantType
	grantType := dataAuth[auth_common.GRANT_TYPE].(string)
	// Switch grantTye
	switch grantType {
	//
	// ============[ Grant_Type: Client Credentials ] ========================================
	case auth_common.GRANT_TYPE_CLIENT_CREDENTIALS:
		/* All validation done already, nothing todo further so just return the result. */

	//
	// ============[ Grant_Type: Password Credentials ] ======================================
	case auth_common.GRANT_TYPE_PASSWORD:

		// Check the scope->client_scope
		if clientScope == auth_common.CLIENT_SCOPE_PLATFORM {
			// ****** Validate the Password credentials with "sysUser" Table ******

			// Authenticate SysUser
			sysUserData, err := authenticateSysUser(dbProps, dataAuth)
			if err != nil {
				return utils.Map{}, err
			}

			sysUserId, _ := utils.GetMemberDataStr(sysUserData, platform_common.FLD_SYS_USER_ID)

			// Update SysUserId to AuthData
			dataAuth[platform_common.FLD_SYS_USER_ID] = sysUserId
		} else {
			// ****** Validate the Password credentials with "appUser" Table ******

			// Authenticate AppUser
			appUserData, err := authenticateAppUser(dbProps, dataAuth)
			if err != nil {
				return utils.Map{}, err
			}

			appUserId, _ := utils.GetMemberDataStr(appUserData, platform_common.FLD_APP_USER_ID)

			businessId, err := utils.GetMemberDataStr(dataAuth, platform_common.FLD_BUSINESS_ID)
			if err == nil {
				// Verify whether this user registered in the businessId which received
				_, err = validateUserRegBusiness(dbProps, businessId, appUserId)
				if err != nil {
					return utils.Map{}, err
				}
			}

			// Update AppUserId to AuthData
			dataAuth[platform_common.FLD_APP_USER_ID] = appUserId
		}
	//
	// ============[ Grant_Type: REFRESH ] ========================================
	case auth_common.GRANT_TYPE_REFRESH:
		/* Need to Implement Refersh Token */
		//dataAuth.RefreshToken = ctx.FormValue("refresh_token")
	}

	// Update Client Data in AuthData
	dataAuth[platform_common.FLD_CLIENT_TYPE] = clientType
	dataAuth[platform_common.FLD_CLIENT_SCOPE] = clientScope

	log.Printf("Auth Values %v", dataAuth)
	return dataAuth, nil
}

/*
************************
For backward compatibility
*************************
*/
func AuthenticateClient(dbProps utils.Map, dataAuth utils.Map) (utils.Map, error) {
	return authenticateClient(dbProps, dataAuth)
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

func validateBusinessId(clientType string, clientScope string, dataAuth utils.Map) (string, error) {
	// Obtain BusinessId value
	var businessId string = ""
	var err error = nil

	switch clientType {
	case auth_common.CLIENT_TYPE_COMMON_APP:
		if clientScope == auth_common.CLIENT_SCOPE_PLATFORM {
			// BusinessId not needed so skip it
		} else {
			// Get Scope values if anything passed
			mapScopes := ParseScope(dataAuth)
			// For all other cases like WebApp, MobileApp and etc
			businessId, err = utils.GetMemberDataStr(mapScopes, auth_common.SCOPE_BUSINESS_ID)
			if err != nil {
				return "", err
			}
		}
	case auth_common.CLIENT_TYPE_BUSINESS_APP:
		// ClientScope will be considered as BusinessId
		businessId = clientScope // Take clientScope as businessId
	}

	return businessId, err
}
