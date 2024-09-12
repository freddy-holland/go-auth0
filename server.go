package main

import (
	"html/template"
	"io"
	"os"

	"fholl.net/auth0/authenticator"
	"fholl.net/auth0/routes"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {

	/*
		Required Variables:
		---
		AUTH0_DOMAIN=...
		AUTH0_CLIENT_ID=...
		AUTH0_CLIENT_SECRET=...
		AUTH0_CALLBACK_URL=...
		SECRET=...
	*/

	// Load .env
	godotenv.Load(".env")

	// Setup auth.
	authenticator.NewAuth()
	authenticator.NewStore(os.Getenv("SECRET"))

	// Setup Echo
	e := echo.New()

	// Setup middleware.
	e.Use(middleware.Logger())

	// Setup templating
	t := &Template{
		templates: template.Must(template.ParseGlob("public/views/*.html")),
	}

	e.Renderer = t

	// Setup Echo routes
	routes.SetupAuthRoutes(e)

	// Start the server.
	e.Logger.Fatal(e.Start(":42069"))
}
