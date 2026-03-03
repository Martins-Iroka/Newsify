package creator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	creatorservice "com.martdev.newsify/internal/service/creator"
	"com.martdev.newsify/internal/util"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type MockCreatorService struct {
	mock.Mock
}

func (m *MockCreatorService) CreateNewsArticle(ctx context.Context, req *creatorservice.CreatorArticleRequestPayload) error {
	arg := m.Called(ctx, req)
	return arg.Error(0)
}

func (m *MockCreatorService) GetNewsArticleById(ctx context.Context, articleId int64, creatorId int64) (*creatorservice.CreatorArticleResponsePayload, error) {
	arg := m.Called(ctx, articleId, creatorId)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}
	return arg.Get(0).(*creatorservice.CreatorArticleResponsePayload), arg.Error(1)
}

func (m *MockCreatorService) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]creatorservice.CreatorArticleResponsePayload, error) {
	arg := m.Called(ctx, creatorID, pagination)
	if arg.Get(0) == nil {
		return make([]creatorservice.CreatorArticleResponsePayload, 0), arg.Error(1)
	}
	return arg.Get(0).([]creatorservice.CreatorArticleResponsePayload), arg.Error(1)
}

func (m *MockCreatorService) DeleteNewsArticle(ctx context.Context, articleID int64, creatorID int64) error {
	arg := m.Called(ctx, articleID, creatorID)
	return arg.Error(0)
}

func (m *MockCreatorService) UpdateNewsArticle(ctx context.Context, articleID int64, newsArticle *creatorservice.CreatorArticleRequestPayload) error {
	arg := m.Called(ctx, articleID, newsArticle)
	return arg.Error(0)
}

func TestCreateNewsArticle(t *testing.T) {
	mockService := new(MockCreatorService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewCreatorHandler(mockService, logger)
	CreateNewsArticle := "CreateNewsArticle"
	const createnewspath = "/createnews"

	t.Run("should create news successfully", func(t *testing.T) {
		reqBody := &creatorservice.CreatorArticleRequestPayload{
			Title:     "title1",
			Content:   "content1",
			CreatorID: 1,
		}
		mockService.On(CreateNewsArticle, mock.Anything, reqBody).Return(nil)
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("unknown field sent", func(t *testing.T) {
		reqBody := struct {
			Title        string `json:"title" validate:"required,max=150"`
			Content      string `json:"content" validate:"required"`
			CreatorID    int64  `json:"creator_id" validate:"required"`
			UnknownField string `json:"unknown"`
		}{
			Title:        "title2",
			Content:      "content2",
			CreatorID:    2,
			UnknownField: "unknown",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, CreateNewsArticle)
	})

	t.Run("title is empty", func(t *testing.T) {
		reqBody := &creatorservice.CreatorArticleRequestPayload{
			Content:   "content3",
			CreatorID: 3,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, CreateNewsArticle)
	})

	t.Run("title is more that 150", func(t *testing.T) {
		reqBody := &creatorservice.CreatorArticleRequestPayload{
			Title:     strings.Repeat("title4", 151),
			Content:   "content4",
			CreatorID: 4,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("content is empty", func(t *testing.T) {
		reqBody := &creatorservice.CreatorArticleRequestPayload{
			Title:     "title5",
			CreatorID: 5,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("creator id is empty", func(t *testing.T) {
		reqBody := &creatorservice.CreatorArticleRequestPayload{
			Title:   "title6",
			Content: "content6",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("should create news return internal server error", func(t *testing.T) {
		reqBody := &creatorservice.CreatorArticleRequestPayload{
			Title:     "title7",
			Content:   "content7",
			CreatorID: 7,
		}
		dbError := errors.New("failed to create news")
		mockService.On(CreateNewsArticle, mock.Anything, reqBody).Return(dbError)
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, createnewspath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.createNewsArticle(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestGetNewsArticleById(t *testing.T) {
	mockService := new(MockCreatorService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewCreatorHandler(mockService, logger)
	GetNewsArticleById := "GetNewsArticleById"
	const getNewsByIdPath = "/creator/1/getNewsArticleById/11"

	t.Run("should get news by id successfully", func(t *testing.T) {
		articleId := int64(11)
		creatorId := int64(1)
		caResponse := &creatorservice.CreatorArticleResponsePayload{
			Title:     "title21",
			Content:   "content21",
			CreatedAt: "createdAt21",
		}
		mockService.On(GetNewsArticleById, mock.Anything, articleId, creatorId).Return(caResponse, nil)

		req := httptest.NewRequest(http.MethodGet, getNewsByIdPath, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "1")
		rctx.URLParams.Add("articleID", "11")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getNewsArticleById(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)

	})

	t.Run("should return bad request for invalid creatorID", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodGet, getNewsByIdPath, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "a")
		rctx.URLParams.Add("articleID", "21")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getNewsArticleById(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, GetNewsArticleById)
	})

	t.Run("should return not found for invalid params", func(t *testing.T) {
		dbError := util.ErrorNotFound
		mockService.On(GetNewsArticleById, mock.Anything, mock.Anything, mock.Anything).Return(nil, dbError)

		req := httptest.NewRequest(http.MethodGet, getNewsByIdPath, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "2")
		rctx.URLParams.Add("articleID", "12")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getNewsArticleById(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestGetAllNewsArticleByCreatorId(t *testing.T) {
	mockService := new(MockCreatorService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewCreatorHandler(mockService, logger)
	GetAllNewsArticleByCreator := "GetAllNewsArticleByCreator"
	const getAllNewsArticleByCreatorIDPath = "/creator/31/getAllNewsArticlesByCreatorID"

	articles := []creatorservice.CreatorArticleResponsePayload{}

	for v := range 5 {
		cna := &creatorservice.CreatorArticleResponsePayload{
			ID:      int64(v),
			Title:   fmt.Sprintf("title%d", v),
			Content: fmt.Sprintf("content%d", v),
		}
		articles = append(articles, *cna)
	}

	t.Run("should get all news articles by creator id successfully", func(t *testing.T) {

		creatorId := int64(32)

		mockService.On(GetAllNewsArticleByCreator, mock.Anything, creatorId, mock.Anything).Return(articles, nil)

		req := httptest.NewRequest(http.MethodGet, getAllNewsArticleByCreatorIDPath, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "32")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getAllNewsArticlesByCreatorId(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("pass query params then get all news articles by creator id successfully", func(t *testing.T) {

		mockService.On(GetAllNewsArticleByCreator, mock.Anything, int64(33), mock.Anything).Return(articles, nil)

		req := httptest.NewRequest(http.MethodGet, "/creator/33/getAllNewsArticlesByCreatorID?limit=20&offset=0", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "33")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getAllNewsArticlesByCreatorId(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("pass invalid creatorID path", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodGet, getAllNewsArticleByCreatorIDPath, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "a")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getAllNewsArticlesByCreatorId(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("invalid query parameters passed", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodGet, "/creator/34/getAllNewsArticlesByCreatorID?limit=invalid", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "34")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getAllNewsArticlesByCreatorId(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("get all news article by creator returns internal server error", func(t *testing.T) {

		creatorId := int64(35)
		internalServerError := errors.New("internal server error")
		mockService.On(GetAllNewsArticleByCreator, mock.Anything, creatorId, mock.Anything).Return(nil, internalServerError)

		req := httptest.NewRequest(http.MethodGet, getAllNewsArticleByCreatorIDPath, nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "35")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.getAllNewsArticlesByCreatorId(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestDeleteNewsArticleByCreator(t *testing.T) {
	mockService := new(MockCreatorService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewCreatorHandler(mockService, logger)
	DeleteNewsArticle := "DeleteNewsArticle"

	t.Run("delete news article successfully", func(t *testing.T) {
		articleID := int64(14)
		creatorID := int64(41)

		mockService.On(DeleteNewsArticle, mock.Anything, articleID, creatorID).Return(nil)

		req := httptest.NewRequest(http.MethodDelete, "/creator/41/deleteNewsArticle/14", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "41")
		rctx.URLParams.Add("articleID", "14")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.deleteNewsArticleByCreator(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("invalid creatorID returns bad request", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodDelete, "/creator/?/deleteNewsArticle/15", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "?")
		rctx.URLParams.Add("articleID", "15")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.deleteNewsArticleByCreator(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("delete news article returns db error response is internal server error", func(t *testing.T) {
		articleID := int64(16)
		creatorID := int64(61)
		dbError := errors.New("db error")

		mockService.On(DeleteNewsArticle, mock.Anything, articleID, creatorID).Return(dbError)

		req := httptest.NewRequest(http.MethodGet, "/creator/61/deleteNewsArticle/16", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("creatorID", "61")
		rctx.URLParams.Add("articleID", "16")

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.deleteNewsArticleByCreator(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}
