package auth_services

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/zapscloud/golib-auth/auth_common"
	"github.com/zapscloud/golib-platform/platform_common"
	"github.com/zapscloud/golib-platform/platform_services"
	"github.com/zapscloud/golib-utils/utils"
)

// func GetFunctionList(app_functions []app.AppFunction) (functions []string) {
// 	for _, value := range app_functions {
// 		functions = append(functions, value.String())
// 	}
// 	return
// }

func getBearerAuth(ctx *fiber.Ctx) (string, error) {
	// Get authorization header
	authstring := ctx.Get(fiber.HeaderAuthorization)

	//log.Println("GetBearerAuth Token:", authstring)

	// Check if the header contains content besides "bearer".
	if len(authstring) <= 7 || strings.ToLower(authstring[:6]) != auth_common.TOKEN_BEARER {
		err := &utils.AppError{
			ErrorStatus: 401,
			ErrorCode:   "401",
			ErrorMsg:    "Bad Request Bearer Header",
			ErrorDetail: "Missing Authorization Bearer Header"}
		return "", err
	}

	// Decode the header contents
	authtoken := authstring[7:]
	if len(authtoken) < 1 {
		err := &utils.AppError{
			ErrorStatus: 401,
			ErrorMsg:    "Bad Request Bearer Token",
			ErrorDetail: "Missing Authorization Bearer Token"}
		return "", err
	}

	//log.Println("Auth Token ", authtoken)
	return authtoken, nil

}

// validateBearerAuth -- Authenticate Application Request
func ValidateBearerAuth(ctx *fiber.Ctx, claims jwt.Claims) error {

	//log.Printf("ValidateBearerAuth %v", ctx.Request().Header.String())

	// verify auth credentials
	authtoken, err := getBearerAuth(ctx)
	//log.Println("Bearer Auth Token ", authtoken, err)
	if err != nil {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Invalid Access", ErrorDetail: "Authentication Failure"}
		return err
	}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	jwtKey := auth_common.GetJwtKey()

	tkn, err := jwt.ParseWithClaims(authtoken, claims, func(token *jwt.Token) (interface{}, error) {
		//log.Println("Token value ", token)
		jwtByte := []byte(jwtKey)
		return jwtByte, nil
	})
	log.Println("JWT Parse ", tkn, err, claims)

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Access Denied", ErrorDetail: "Invalid Signature"}
			return err
		}

		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Access Denied", ErrorDetail: err.Error()}
		return err
	}
	if !tkn.Valid {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Access Denied", ErrorDetail: "Invalid Token"}
		return err
	}

	log.Printf("Auth Values %v", claims)
	return nil
}

func parseScope(scope_value string) utils.Map {

	mapScopes := utils.Map{}

	scopeStrings := strings.Fields(scope_value)
	for _, scopeString := range scopeStrings {
		scopeValue := strings.Split(scopeString, ":")
		if len(scopeValue) > 1 {
			mapScopes[scopeValue[0]] = scopeValue[1]
		}
	}

	return mapScopes
}

func authenticateSysUser(dbProps utils.Map, dataAuth utils.Map) (utils.Map, error) {

	// Get Scope values if anything passed
	mapScopes := ParseScope(dataAuth)

	// Default authKey is user_id
	authKey := platform_common.FLD_SYS_USER_ID

	loginType, _ := utils.GetMemberDataStr(mapScopes, auth_common.LOGIN_TYPE)
	if loginType == auth_common.LOGIN_TYPE_EMAIL {
		authKey = platform_common.FLD_SYS_USER_EMAILID
	} else if loginType == auth_common.LOGIN_TYPE_PHONE {
		authKey = platform_common.FLD_SYS_USER_PHONE
	}

	authKeyValue := dataAuth[auth_common.USERNAME].(string)
	authPassword := dataAuth[auth_common.PASSWORD].(string)

	serviceSysUser, err := platform_services.NewSysUserService(dbProps)
	if err != nil {
		err := &utils.AppError{ErrorStatus: 417, ErrorMsg: "Status Expectation Failed", ErrorDetail: "Authentication Failure"}
		return utils.Map{}, err
	}
	defer serviceSysUser.EndService()

	log.Println("authenticateSysUser::Auth:: Parameter Value ", authKey, authKeyValue)
	sysUserData, err := serviceSysUser.Authenticate(authKey, authKeyValue, authPassword)
	if err != nil {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Status Unauthorized", ErrorDetail: "Authentication Failure"}
		return utils.Map{}, err
	}

	return sysUserData, nil
}

func authenticateAppUser(dbProps utils.Map, dataAuth utils.Map) (utils.Map, error) {

	// Get Scope values if anything passed
	mapScopes := ParseScope(dataAuth)

	// Default authKey is user_id
	authKey := platform_common.FLD_APP_USER_ID

	loginType, _ := utils.GetMemberDataStr(mapScopes, auth_common.LOGIN_TYPE)
	if loginType == auth_common.LOGIN_TYPE_EMAIL {
		authKey = platform_common.FLD_APP_USER_EMAILID
	} else if loginType == auth_common.LOGIN_TYPE_PHONE {
		authKey = platform_common.FLD_APP_USER_PHONE
	}

	authKeyValue := dataAuth[auth_common.USERNAME].(string)
	authPassword := dataAuth[auth_common.PASSWORD].(string)

	// User Validation
	serviceAppUser, err := platform_services.NewAppUserService(dbProps)

	if err != nil {
		err := &utils.AppError{ErrorStatus: 417, ErrorMsg: "Status Expectation Failed", ErrorDetail: "Authentication Failure"}
		return utils.Map{}, err
	}
	defer serviceAppUser.EndService()

	log.Println("authenticateAppUser::Auth Parameter Value ", authKey, authKeyValue)
	appUserData, err := serviceAppUser.Authenticate(authKey, authKeyValue, authPassword)
	if err != nil {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Status Unauthorized", ErrorDetail: "Authentication Failure"}
		return utils.Map{}, err
	}

	return appUserData, nil
}
