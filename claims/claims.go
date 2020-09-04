package claims

import (
	"time"

	"github.com/moisespsena-go/maps"

	jwt "github.com/dgrijalva/jwt-go"
)

// Claims auth claims
type Claims struct {
	Parent                           *Claims        `json:"parent,omitempty"`
	Provider                         string         `json:"provider,omitempty"`
	UserID                           string         `json:"userid,omitempty"`
	LastLoginAt                      *time.Time     `json:"last_login,omitempty"`
	LastActiveAt                     *time.Time     `json:"last_active,omitempty"`
	LongestDistractionSinceLastLogin *time.Duration `json:"distraction_time,omitempty"`
	Data                             maps.MapSI     `json:"data,omitempty"`
	DeleteCallbacks                  []string       `json:"delete_callbacks,omitempty"`
	IsAdmin                          bool           `json:"admin,omitempty"`
	jwt.StandardClaims
}

// ToClaims implement ClaimerInterface
func (claims *Claims) ToClaims() *Claims {
	return claims
}

// ClaimerInterface claimer interface
type ClaimerInterface interface {
	ToClaims() *Claims
}
