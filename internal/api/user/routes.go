package user

import "github.com/go-chi/chi/v5"

func (h *Handler) RegisterRoutes(r *chi.Mux) {
	r.Route("/authentication", func(r chi.Router) {
		r.Post("/register", h.registerUserHandler)
		r.Post("/verify", h.verifyUserHandler)
		r.Post("/login", h.loginUserHandler)
		r.Post("/refresh", h.refreshTokenHandler)
		r.Post("{refreshToken}/logout", h.logoutUserHandler)
	})
}
