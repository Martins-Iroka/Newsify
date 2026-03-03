package creator

import (
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
//
//	@failure	400			{object}	util.ErrorResponse
//	@failure	404			{object}	util.ErrorResponse
//
//	@failure	500			{object}	util.ErrorResponse
//	@router		/creator/{creatorID}/getNewsArticleById/{articleID} [get]
func (h *CreatorHandler) getNewsArticleById(w http.ResponseWriter, r *http.Request) {
	creatorIDParam := chi.URLParam(r, "creatorID")
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

type ArticleResponse struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatorID int64  `json:"creator_id"`
	CreatedAt string `json:"created_at"`
}

type CreatorNewsArticlesPayload struct {
	NewsArticles []ArticleResponse `json:"news_articles"`
	NextPage     int               `json:"next_page"`
}

// Get all news articles by creator
//
//	@summary	Get all news articles
//	@tags		creator
//	@accept		json
//	@param		creatorID	path		int	true	"Creator ID"
//	@param		limit		query		int	false	"Limit"
//	@param		offset		query		int	false	"Offset"
//	@success	200			{object}	util.DataResponse{data=CreatorNewsArticlesPayload}
//	@failure	400			{object}	util.ErrorResponse
//	@failure	500			{object}	util.ErrorResponse
//	@router		/creator/{creatorID}/getAllNewsArticles [get]
func (h *CreatorHandler) getAllNewsArticlesByCreatorId(w http.ResponseWriter, r *http.Request) {
	creatorIDParam := chi.URLParam(r, "creatorID")
	creatorID, err := strconv.ParseInt(creatorIDParam, 10, 64)
	if err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	p := util.PaginatedFeedQueryAPI{
		Limit:  20,
		Offset: 0,
	}

	p, err = p.Parse(r)
	if err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(p); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	paginate := util.PaginatedPostQuery(p)

	results, err := h.service.GetAllNewsArticleByCreator(r.Context(), creatorID, paginate)
	if err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
		return
	}

	nextOffset := p.Offset + p.Limit
	if len(results) < p.Limit {
		nextOffset = -1
	}

	creatorNewsArticles := []ArticleResponse{}

	for _, ca := range results {
		newsArticle := &ArticleResponse{
			ID:        ca.ID,
			Title:     ca.Title,
			Content:   ca.Content,
			CreatorID: ca.CreatorID,
			CreatedAt: ca.CreatedAt,
		}

		creatorNewsArticles = append(creatorNewsArticles, *newsArticle)
	}

	cna := CreatorNewsArticlesPayload{
		NewsArticles: creatorNewsArticles,
		NextPage:     nextOffset,
	}

	if err := util.JSONResponse(w, http.StatusOK, cna); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
	}
}

// Delete news articles by creator
//
//	@summary	Creator deletes a new article
//	@tags		creator
//	@accept		json
//	@param		creatorID	path	int	true	"Creator ID"
//	@param		articleID	path	int	true	"Article ID"
//	@success	200			"Success"
//	@failure	400			{object}	util.ErrorResponse
//	@failure	500			{object}	util.ErrorResponse
//	@router		/creator/{creatorID}/deleteNewsArticle/{articleID} [delete]
func (h *CreatorHandler) deleteNewsArticleByCreator(w http.ResponseWriter, r *http.Request) {
	creatorIDParam := chi.URLParam(r, "creatorID")
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

	err = h.service.DeleteNewsArticle(r.Context(), articleID, creatorID)
	if err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
		return
	}

	w.WriteHeader(http.StatusOK)
}
