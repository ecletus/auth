package auth

import (
	"fmt"

	"github.com/ecletus/auth/claims"
)

// Provider define Provider interface
type Provider interface {
	GetName() string

	ConfigAuth(*Auth)
	PrepareLoginContext(*LoginContext) error
	Login(*LoginContext) (*claims.Claims, error)
	Logout(*Context)
	Register(*Context)
	Callback(*Context)
	ServeHTTP(*Context)
	I18n(key ...string) string
}

// RegisterProvider register auth provider
func (auth *Auth) RegisterProvider(provider Provider) {
	name := provider.GetName()
	if _, ok := auth.providers[name]; ok {
		fmt.Printf("warning: auth provider %v already registered", name)
		return
	}

	provider.ConfigAuth(auth)
	auth.providers[name] = provider
}

// GetProvider get provider with name
func (auth *Auth) GetProvider(name string) Provider {
	return auth.providers[name]
}

// GetProviders return registered providers
func (auth *Auth) GetProviders() (providers []Provider) {
	for _, provider := range auth.providers {
		providers = append(providers, provider)
	}
	return
}
