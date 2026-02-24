package creator

import "github.com/go-chi/chi/v5"

func (h *CreatorHandler) RegisterCreatorRoutes(r chi.Router) {
	r.Route("/creator", func(r chi.Router) {
		r.Post("/createnews", h.createNewsArticle)
	})
}
