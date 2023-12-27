package auth_services

import "log"

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
