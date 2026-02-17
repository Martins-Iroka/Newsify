package creator

import (
	"context"
	"errors"
	"fmt"
	"testing"

	dbCreator "com.martdev.newsify/internal/database/creator"
	"com.martdev.newsify/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

		service := NewCreatorService(mockStore)

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

		service := NewCreatorService(mockStore)
		dbError := errors.New("db error")

		mockStore.On(createNewsArticle, mock.Anything, mock.Anything).Return(dbError)

		err := service.CreateNewsArticle(t.Context(), &req)
		require.Error(t, err)
		assert.EqualError(t, err, dbError.Error())

		mockStore.AssertExpectations(t)
	})
}

func TestGetNewsArticleById(t *testing.T) {
	getNewsArticleById := "GetNewsArticleById"
	articleId := int64(1)
	creatorId := int64(11)

	t.Run("get news article by id returns valid response", func(t *testing.T) {
		articleResponse := &dbCreator.CreatorArticle{
			Title:     "title2",
			Content:   "content2",
			CreatedAt: "01/01/2001",
		}

		mockStore := new(MockCreatorStore)
		service := NewCreatorService(mockStore)

		mockStore.On(getNewsArticleById, mock.Anything, mock.MatchedBy(func(cid int64) bool {
			return creatorId == cid
		}), mock.MatchedBy(func(aid int64) bool {
			return articleId == aid
		})).Return(articleResponse, nil)

		res, err := service.GetNewsArticleById(t.Context(), articleId, creatorId)
		require.NoError(t, err)
		require.Equal(t, "title2", res.Title)
		require.Equal(t, "content2", res.Content)
		assert.Equal(t, "01/01/2001", res.CreatedAt)

		mockStore.AssertExpectations(t)
	})

	t.Run("get news article by id returns error from db", func(t *testing.T) {
		mockStore := new(MockCreatorStore)
		service := NewCreatorService(mockStore)

		dbError := errors.New("error getting news by id")

		mockStore.On(getNewsArticleById, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, dbError)

		res, err := service.GetNewsArticleById(t.Context(), articleId, creatorId)
		require.Nil(t, res)
		require.Error(t, err)
		assert.EqualError(t, err, dbError.Error())

		mockStore.AssertExpectations(t)
	})
}

func TestGetAllNewsArticleByCreator(t *testing.T) {
	getAllNewsArticleByCreator := "GetAllNewsArticleByCreator"
	creatorID := int64(12)
	pagination := util.PaginatedPostQuery{
		Limit:  5,
		Offset: 1,
	}
	t.Run("get all news article by creator", func(t *testing.T) {
		articles := []dbCreator.CreatorArticle{}

		for v := range 5 {
			ca := dbCreator.CreatorArticle{
				ID:    int64(v),
				Title: fmt.Sprintf("title%d", v),
			}
			articles = append(articles, ca)
		}
		mockStore := new(MockCreatorStore)
		service := NewCreatorService(mockStore)

		mockStore.On(getAllNewsArticleByCreator, mock.Anything, mock.MatchedBy(func(cid int64) bool {
			return creatorID == cid
		}), mock.Anything).Return(articles, nil)

		res, err := service.GetAllNewsArticleByCreator(t.Context(), creatorID, pagination)
		require.NoError(t, err)
		require.NotEmpty(t, res)
		assert.Len(t, res, 5)

		mockStore.AssertExpectations(t)
	})

	t.Run("get all news article by creator returns empty list", func(t *testing.T) {
		empty := make([]dbCreator.CreatorArticle, 0)

		mockStore := new(MockCreatorStore)
		service := NewCreatorService(mockStore)

		mockStore.On(getAllNewsArticleByCreator, mock.Anything, mock.Anything, mock.Anything).
			Return(empty, nil)

		res, err := service.GetAllNewsArticleByCreator(t.Context(), creatorID, pagination)
		require.NoError(t, err)
		assert.Empty(t, res)

		mockStore.AssertExpectations(t)
	})

	t.Run("get all news article by creator returns db error", func(t *testing.T) {
		empty := make([]dbCreator.CreatorArticle, 0)
		dbError := errors.New("error from db")
		mockStore := new(MockCreatorStore)
		service := NewCreatorService(mockStore)

		mockStore.On(getAllNewsArticleByCreator, mock.Anything, mock.Anything, mock.Anything).Return(empty, dbError)

		res, err := service.GetAllNewsArticleByCreator(t.Context(), creatorID, pagination)
		require.Empty(t, res)
		require.Error(t, err)
		assert.ErrorIs(t, err, dbError)

		mockStore.AssertExpectations(t)
	})
}
