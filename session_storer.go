package auth

import (
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/session"
)

// SessionStorerInterface session storer interface for Auth
type SessionStorerInterface interface {
	// Get get claims from request
	Get(manager session.RequestSessionManager) (*claims.Claims, error)
	// Update update claims with session manager
	Update(manager session.RequestSessionManager, claims *claims.Claims) error
	// Delete delete session
	Delete(manager session.RequestSessionManager) error

	// Flash add flash message to session data
	Flash(manager session.RequestSessionManager, message session.Message) error
	// Flashes returns a slice of flash messages from session data
	Flashes(manager session.RequestSessionManager) []session.Message

	// SignedToken generate signed token with Claims
	SignedToken(claims *claims.Claims) string
	// ValidateClaims validate auth token
	ValidateClaims(tokenString string) (*claims.Claims, error)
}

// SessionStorer default session storer
type SessionStorer struct {
	SessionName    string
	SigningMethod  jwt.SigningMethod
	SignedString   string
}

// Get get claims from request
func (sessionStorer *SessionStorer) Get(manager session.RequestSessionManager) (*claims.Claims, error) {
	tokenString := manager.Request().Header.Get("Authorization")

	// Get Token from Cookie
	if tokenString == "" {
		tokenString = manager.Get(sessionStorer.SessionName)
	}

	return sessionStorer.ValidateClaims(tokenString)
}

// Update update claims with session manager
func (sessionStorer *SessionStorer) Update(manager session.RequestSessionManager, claims *claims.Claims) error {
	token := sessionStorer.SignedToken(claims)
	return manager.Add(sessionStorer.SessionName, token)
}

// Delete delete claims from session manager
func (sessionStorer *SessionStorer) Delete(manager session.RequestSessionManager) error {
	manager.Pop(sessionStorer.SessionName)
	return nil
}

// Flash add flash message to session data
func (sessionStorer *SessionStorer) Flash(manager session.RequestSessionManager, message session.Message) error {
	return manager.Flash(message)
}

// Flashes returns a slice of flash messages from session data
func (sessionStorer *SessionStorer) Flashes(manager session.RequestSessionManager) []session.Message {
	return manager.Flashes()
}

// SignedToken generate signed token with Claims
func (sessionStorer *SessionStorer) SignedToken(claims *claims.Claims) string {
	token := jwt.NewWithClaims(sessionStorer.SigningMethod, claims)
	signedToken, _ := token.SignedString([]byte(sessionStorer.SignedString))

	return signedToken
}

// ValidateClaims validate auth token
func (sessionStorer *SessionStorer) ValidateClaims(tokenString string) (*claims.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != sessionStorer.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(sessionStorer.SignedString), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*claims.Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
