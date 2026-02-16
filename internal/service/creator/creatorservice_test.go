package creator

import (
	"context"
	"errors"
	"testing"

	dbCreator "com.martdev.newsify/internal/database/creator"
	"com.martdev.newsify/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type MockCreatorStore struct {
	mock.Mock
}

func (m *MockCreatorStore) CreateNewsArticle(ctx context.Context, ca *dbCreator.CreatorArticle) error {
	return m.Called(ctx, ca).Error(0)
}

func (m *MockCreatorStore) GetNewsArticleById(ctx context.Context, creatorID int64, articleID int64) (*dbCreator.CreatorArticle, error) {
	args := m.Called(ctx, creatorID, articleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbCreator.CreatorArticle), args.Error(1)
}

func (m *MockCreatorStore) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]dbCreator.CreatorArticle, error) {
	args := m.Called(ctx, creatorID, pagination)
	if args.Get(0) == nil {
		return make([]dbCreator.CreatorArticle, 0), nil
	}
	return args.Get(0).([]dbCreator.CreatorArticle), args.Error(1)
}

func (m *MockCreatorStore) DeleteNewsArticle(ctx context.Context, creatorID int64, articleID int64) error {
	return m.Called(ctx, creatorID, articleID).Error(0)
}

func (m *MockCreatorStore) UpdateNewsArticle(ctx context.Context, newsArticle *dbCreator.CreatorArticle) error {
	return m.Called(ctx, newsArticle).Error(0)
}

func TestCreateNewsArticleService(t *testing.T) {
	req := CreatorArticleRequestPayload{
		Title:     "title1",
		Content:   "content1",
		CreatorID: 1,
	}
	createNewsArticle := "CreateNewsArticle"
	t.Run("create news article successfully", func(t *testing.T) {
		mockStore := new(MockCreatorStore)
		logger := zaptest.NewLogger(t).Sugar()

		service := NewCreatorService(mockStore, logger)

		mockStore.On(createNewsArticle, mock.Anything, mock.MatchedBy(func(ca *dbCreator.CreatorArticle) bool {
			return ca.Title == req.Title &&
				ca.Content == req.Content &&
				ca.CreatorID == req.CreatorID
		})).Return(nil)

		err := service.CreateNewsArticle(t.Context(), &req)
		assert.NoError(t, err)

		mockStore.AssertExpectations(t)
	})

	t.Run("create news article failed returns db error", func(t *testing.T) {
		mockStore := new(MockCreatorStore)
		logger := zaptest.NewLogger(t).Sugar()

		service := NewCreatorService(mockStore, logger)
		dbError := errors.New("db error")

		mockStore.On(createNewsArticle, mock.Anything, mock.Anything).Return(dbError)

		err := service.CreateNewsArticle(t.Context(), &req)
		require.Error(t, err)
		assert.EqualError(t, err, dbError.Error())

		mockStore.AssertExpectations(t)
	})
}
