package tokens

import (
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Structure for storing data about refresh token, access token link, user data
type RefreshToken struct {
	Token           string
	HashRefresh     string
	AccessToken     string
	Ip              string
	TimeCreate      time.Time
	UuidAccessToken string
}

// Generates a refresh key with a reference to the access token
func GenerateRefreshToken(uuidAccessToken string) (RefreshToken, error) {
	token := base64.StdEncoding.EncodeToString([]byte(uuidAccessToken))
	hash, err := bcrypt.GenerateFromPassword([]byte(token), 10)
	if err != nil {
		return RefreshToken{}, nil
	}
	var refreshToken RefreshToken = RefreshToken{Token: token, HashRefresh: string(hash), TimeCreate: time.Now()}
	return refreshToken, nil
}

// Generates a access JWT key with SHA512
func GenerateAccessToken(uuid string) (string, error) {
	claim := jwt.MapClaims{
		"uuid": uuid,
	}
	jwtObject := jwt.NewWithClaims(jwt.SigningMethodHS512, claim)
	token, err := jwtObject.SignedString([]byte(uuid))
	if err != nil {
		return "", err
	}
	return token, nil
}

// Checks whether access and refresh tokens are in the bundle based on the input data
func CheckValidTokens(uuid uuid.UUID, accessToken string, refreshToken string) (bool, error) {
	CheckAccessToken, err := GenerateAccessToken(uuid.String())
	if err != nil {
		return false, err
	}
	checkRefreshToken, err := GenerateRefreshToken(uuid.String())
	if err != nil {
		return false, err
	}
	return accessToken == CheckAccessToken && refreshToken == checkRefreshToken.Token, nil
}

// Generate random uuid id
func GenerateUUID() (string, error) {
	uuid, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	return uuid.String(), nil
}
