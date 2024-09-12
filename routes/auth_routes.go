package routes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"fholl.net/auth0/authenticator"
	"github.com/labstack/echo/v4"
)

func SetupAuthRoutes(e *echo.Echo) {

	gob.Register(map[string]interface{}{})

	e.GET("/login", loginHandler)
	e.GET("/callback", callbackHandler)
	e.GET("/logout", logoutHandler)

	e.GET("/user", func(c echo.Context) error {
		session, _ := authenticator.SessionStore.Get(c.Request(), "auth-session")
		profile := session.Values["profile"]
		return c.Render(http.StatusOK, "user", profile)
	})
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)
	return state, nil
}

func loginHandler(c echo.Context) error {

	state, err := generateRandomState()
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Error generating random state: %v", err.Error()))
	}

	session, _ := authenticator.SessionStore.Get(c.Request(), "auth-session")

	session.Values["state"] = state
	err = session.Save(c.Request(), c.Response().Writer)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	return c.Redirect(http.StatusTemporaryRedirect, authenticator.Auth.AuthCodeURL(state))
}

func callbackHandler(c echo.Context) error {

	session, _ := authenticator.SessionStore.Get(c.Request(), "auth-session")

	if c.QueryParam("state") != session.Values["state"] {
		return c.String(http.StatusBadRequest, "Invalid state parameter")
	}

	token, err := authenticator.Auth.Exchange(c.Request().Context(), c.QueryParam("code"))
	if err != nil {
		return c.String(http.StatusUnauthorized, "Failed to exchange code for token")
	}

	idToken, err := authenticator.Auth.VerifyIDToken(c.Request().Context(), token)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to verify ID token")
	}

	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile

	err = session.Save(c.Request(), c.Response().Writer)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	return c.Redirect(http.StatusTemporaryRedirect, "/")
}

func logoutHandler(c echo.Context) error {
	logoutUrl, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	scheme := "http"
	if c.Request().TLS != nil {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" + c.Request().Host)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	params := url.Values{}
	params.Add("returnTo", returnTo.String())
	params.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = params.Encode()

	return c.Redirect(http.StatusTemporaryRedirect, logoutUrl.String())
}
