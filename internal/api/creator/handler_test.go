package creator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	creatorservice "com.martdev.newsify/internal/service/creator"
	"com.martdev.newsify/internal/util"
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
