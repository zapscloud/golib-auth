package auth_services

import (
	"log"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/zapscloud/golib-auth/auth_common"
	"github.com/zapscloud/golib-platform-repository/platform_common"
	"github.com/zapscloud/golib-platform-service/platform_service"
	"github.com/zapscloud/golib-utils/utils"
)

// validateBearerAuth -- Authenticate Application Request
func validateBearerAuth(authToken string, claims jwt.Claims) error {

	// Check if the header contains content besides "bearer".
	if len(authToken) <= 7 || strings.ToLower(authToken[:6]) != auth_common.TOKEN_BEARER {
		err := &utils.AppError{
			ErrorStatus: 401,
			ErrorCode:   "401",
			ErrorMsg:    "Bad Request Bearer Header",
			ErrorDetail: "Missing Authorization Bearer Header"}
		return err
	}

	// Decode the header contents
	authtoken := authToken[7:]
	if len(authtoken) < 1 {
		err := &utils.AppError{
			ErrorStatus: 401,
			ErrorMsg:    "Bad Request Bearer Token",
			ErrorDetail: "Missing Authorization Bearer Token"}
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

func authenticateClient(dbProps utils.Map, dataAuth utils.Map) (utils.Map, error) {

	// Get clientId and clientSecret
	clientId, err := utils.GetMemberDataStr(dataAuth, auth_common.CLIENT_ID)
	if err != nil {
		return nil, err
	}
	clientSecret, err := utils.GetMemberDataStr(dataAuth, auth_common.CLIENT_SECRET)
	if err != nil {
		return nil, err
	}

	// Create Service Instance
	clientService, err := platform_service.NewClientsService(dbProps)
	if err != nil {
		log.Println("Client DB Error ", err)
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Client DB Connection Error", ErrorDetail: "Client DB Connection Error"}
		return nil, err
	}
	defer clientService.EndService()

	log.Println("authenticateAppClient ", clientId, clientSecret)

	clientData, err := clientService.Authenticate(clientId, clientSecret)
	if err != nil {
		log.Println("Auth DB Error ", err)
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Invalid Access", ErrorDetail: "Authentication Failure"}
		return nil, err
	}

	return clientData, err
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

	authKeyValue := strings.ToLower(dataAuth[auth_common.USERNAME].(string))
	authPassword := dataAuth[auth_common.PASSWORD].(string)

	serviceSysUser, err := platform_service.NewSysUserService(dbProps)
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

	authKeyValue := strings.ToLower(dataAuth[auth_common.USERNAME].(string))
	authPassword := dataAuth[auth_common.PASSWORD].(string)

	// User Validation
	serviceAppUser, err := platform_service.NewAppUserService(dbProps)

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

func isBusinessExist(dbProps utils.Map, businessId string) (utils.Map, error) {
	// User Validation
	bizService, err := platform_service.NewBusinessService(dbProps)
	if err != nil {
		err := &utils.AppError{ErrorStatus: 417, ErrorMsg: "Status Expectation Failed", ErrorDetail: "Authentication Failure"}
		return nil, err
	}
	defer bizService.EndService()

	log.Println("isBusinessExist::Parameter Value ", businessId)
	bizData, err := bizService.Get(businessId)
	if err != nil {
		err := &utils.AppError{ErrorStatus: 401, ErrorMsg: "Invalid BusinessId", ErrorDetail: "No such BusinessId found"}
		return nil, err
	}

	return bizData, nil
}

func validateUserRegBusiness(dbProps utils.Map, businessId, appUserId string) (utils.Map, error) {
	// User Validation
	svcAppUser, err := platform_service.NewAppUserService(dbProps)
	if err != nil {
		err := &utils.AppError{
			ErrorStatus: 417,
			ErrorMsg:    "Status Expectation Failed",
			ErrorDetail: "Authentication Failure"}
		return nil, err
	}
	defer svcAppUser.EndService()

	log.Println("isBusinessExist::Parameter Value ", businessId)
	bizData, err := svcAppUser.BusinessUser(businessId, appUserId)
	if err != nil {
		err := &utils.AppError{
			ErrorStatus: 401,
			ErrorMsg:    "Invalid BusinessId/UserId",
			ErrorDetail: "User not registered with this business"}
		return nil, err
	}

	return bizData, nil

}
