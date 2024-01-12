package auth_services

import (
	"log"

	"github.com/zapscloud/golib-auth/auth_common"
	"github.com/zapscloud/golib-utils/utils"
)

func AuthValidateWithToken(authToken string) (Claims, error) { // for validation process
	//  validation process Start
	claims := Claims{}

	err := validateBearerAuth(authToken, &claims)
	if err != nil {
		log.Println("Error at AuthValidateWithToken => ", err)
		return claims, err
	}
	log.Println("AuthValidateWithToken::Claims", claims)

	return claims, nil
}

func GetBasicAuthWithToken(authToken string) (string, string, error) {

	return getBasicAuth(authToken)

}

func ValidateInputParamsWithToken(authToken string, authData utils.Map) (utils.Map, error) {

	dataAuth := utils.Map{
		auth_common.GRANT_TYPE:    authData[auth_common.GRANT_TYPE],
		auth_common.CLIENT_ID:     authData[auth_common.CLIENT_ID],
		auth_common.CLIENT_SECRET: authData[auth_common.CLIENT_SECRET],
		auth_common.USERNAME:      authData[auth_common.USERNAME],
		auth_common.PASSWORD:      authData[auth_common.PASSWORD],
		auth_common.REFRESH_TOKEN: authData[auth_common.REFRESH_TOKEN],
		auth_common.SCOPE:         authData[auth_common.SCOPE],
	}

	// verify auth credentials
	clientId, clientSecret, err := GetBasicAuthWithToken(authToken)
	if err == nil {
		dataAuth[auth_common.CLIENT_ID] = clientId
		dataAuth[auth_common.CLIENT_SECRET] = clientSecret
	}

	log.Println("ValidateInputParamsWithToken : ", dataAuth)

	return validateAuthData(dataAuth)
}
