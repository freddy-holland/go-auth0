package authenticator

import (
	"context"
	"errors"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var SessionStore *sessions.CookieStore

func NewStore(secret string) {
	SessionStore = sessions.NewCookieStore([]byte(secret))
}

type Authenticator struct {
	*oidc.Provider
	oauth2.Config
}

var Auth *Authenticator

func NewAuth() error {
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+os.Getenv("AUTH0_DOMAIN")+"/",
	)

	if err != nil {
		return err
	}

	conf := oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	Auth = &Authenticator{
		Provider: provider,
		Config:   conf,
	}

	return nil
}

func (a *Authenticator) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: a.ClientID,
	}

	return a.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}
