package creator

import (
	"net/http"

	creatorservice "com.martdev.newsify/internal/service/creator"
	"com.martdev.newsify/internal/util"
	"go.uber.org/zap"
)

type CreatorHandler struct {
	service creatorservice.CreatorService
	logger  *zap.SugaredLogger
}

func NewCreatorHandler(service creatorservice.CreatorService, logger *zap.SugaredLogger) *CreatorHandler {
	return &CreatorHandler{service: service, logger: logger}
}

// Create news article godoc
//
//	@summary	Create news article by creators
//	@tags		creator
//	@accept		json
//	@param		payload	body	creator.CreatorArticleRequestPayload	true	"News info"
//	@success	201
//	@failure	400	{object}	util.ErrorResponse
//	@failure	500	{object}	util.ErrorResponse
//	@router		/creator/createnews [post]
func (h *CreatorHandler) createNewsArticle(w http.ResponseWriter, r *http.Request) {
	var req creatorservice.CreatorArticleRequestPayload

	if err := util.ReadJSON(w, r, &req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := h.service.CreateNewsArticle(r.Context(), &req); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
