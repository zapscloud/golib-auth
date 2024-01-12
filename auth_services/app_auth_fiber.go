package auth_services

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/zapscloud/golib-auth/auth_common"
	"github.com/zapscloud/golib-utils/utils"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.Lmicroseconds)
}

func AuthValidate(ctx *fiber.Ctx) (Claims, error) { // for validation process
	//  validation process Start
	claims := Claims{}

	// Get authorization header
	authToken := ctx.Get(fiber.HeaderAuthorization)

	err := validateBearerAuth(authToken, &claims)
	if err != nil {
		log.Println("err for final ", err)
		return claims, err
	}
	log.Println("auth", claims)

	return claims, nil
}

func GetBasicAuth(ctx *fiber.Ctx) (string, string, error) {
	// Get authorization header
	authstring := ctx.Get(fiber.HeaderAuthorization)

	return getBasicAuth(authstring)

}

func ParseScope(dataAuth utils.Map) utils.Map {
	mapScopes := utils.Map{}
	if scopeValue, scopeOk := dataAuth[auth_common.SCOPE]; scopeOk && !utils.IsEmpty(scopeValue.(string)) {
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

	return validateAuthData(dataAuth)
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
