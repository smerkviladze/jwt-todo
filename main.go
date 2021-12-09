package main

import (
	"jwt-todo/controller"

	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Group(func(r chi.Router) {
		r.Use(controller.TokenAuthMiddleware)
		r.Post("/logout", controller.Logout)
		r.Post("/todo", controller.CreateTodo)
	})

	r.Post("/login", controller.Login)
	r.Post("/token/refresh", controller.Refresh)

	http.ListenAndServe(":3000", r)

}
