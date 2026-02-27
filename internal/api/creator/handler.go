package creator

import (
	"fmt"
	"net/http"
	"strconv"

	creatorservice "com.martdev.newsify/internal/service/creator"
	"com.martdev.newsify/internal/util"
	"github.com/go-chi/chi/v5"
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
//	@summary	Creators publish news article
//	@tags		creator
//	@accept		json
//	@param		payload	body	creator.CreatorArticleRequestPayload	true	"News info"
//	@success	201
//	@failure	400	{object}	util.ErrorResponse
//	@failure	500	{object}	util.ErrorResponse
//	@router		/creator/createNews [post]
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

// Get news article by id godoc
//
//	@summary	Creator get their news article using their id
//	@tags		creator
//	@accept		json
//	@param		creatorID	path		int	true	"Creator ID"
//	@param		articleID	path		int	true	"Article ID"
//	@success	200			{object}	util.DataResponse{data=CreatorArticleResponsePayload}
//	@failure	500			{object}	util.ErrorResponse
//	@router		/creator/{creatorID}/getNewsArticleById/{articleID} [get]
func (h *CreatorHandler) getNewsArticleById(w http.ResponseWriter, r *http.Request) {
	creatorIDParam := chi.URLParam(r, "creatorID")
	fmt.Printf("creatorID is %s", creatorIDParam)
	creatorID, err := strconv.ParseInt(creatorIDParam, 10, 64)
	if err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	articleIDParam := chi.URLParam(r, "articleID")
	articleID, err := strconv.ParseInt(articleIDParam, 10, 64)
	if err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	newsArticle, err := h.service.GetNewsArticleById(r.Context(), articleID, creatorID)
	if err != nil {
		switch err {
		case util.ErrorNotFound:
			util.NotFoundErrorResponse(w, r, err, h.logger)
		default:
			util.InternalServerErrorResponse(w, r, err, h.logger)
		}
		return
	}

	if err := util.JSONResponse(w, http.StatusOK, newsArticle); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
	}
}
