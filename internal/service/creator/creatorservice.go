package creator

import (
	"context"

	"com.martdev.newsify/internal/database/creator"
	"com.martdev.newsify/internal/util"
	"go.uber.org/zap"
)

type CreatorArticleRequestPayload struct {
	Title     string `json:"title" validate:"required"`
	Content   string `json:"content" validate:"required"`
	CreatorID int64  `json:"creator_id" validate:"required"`
}

type CreatorArticleResponsePayload struct {
	ID        int64  `json:"id"`
	Title     string `json:"title" `
	Content   string `json:"content" `
	CreatorID int64  `json:"creator_id"`
	CreatedAt string `json:"created_at"`
}

type CreatorNewsArticlesPayload struct {
	NewsArticles []CreatorArticleResponsePayload `json:"news_articles"`
	Next         int                             `json:"next"`
}

type CreatorService interface {
	CreateNewsArticle(context.Context, *CreatorArticleRequestPayload) error
	GetNewsArticleById(ctx context.Context, articleID int64, creatorID int64) (*CreatorArticleResponsePayload, error)
	GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]CreatorArticleResponsePayload, error)
	DeleteNewsArticle(ctx context.Context, articleID int64, creatorID int64) error
	UpdateNewsArticle(ctx context.Context, articleID int64, newsArticle *CreatorArticleRequestPayload) error
}

type CreatorArticleService struct {
	store  creator.CreatorStore
	logger *zap.SugaredLogger
}

func NewCreatorService(store creator.CreatorStore, logger *zap.SugaredLogger) *CreatorArticleService {
	return &CreatorArticleService{
		store:  store,
		logger: logger,
	}
}

func (c *CreatorArticleService) CreateNewsArticle(ctx context.Context, creatorArticle *CreatorArticleRequestPayload) error {
	return nil
}

func (c *CreatorArticleService) GetNewsArticleById(ctx context.Context, articleID int64, creatorID int64) (*CreatorArticleResponsePayload, error) {
	return nil, nil
}

func (c *CreatorArticleService) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]CreatorArticleResponsePayload, error) {
	return make([]CreatorArticleResponsePayload, 0), nil
}

func (c *CreatorArticleService) DeleteNewsArticle(ctx context.Context, articleID int64, creatorID int64) error {
	return nil
}

func (c *CreatorArticleService) UpdateNewsArticle(ctx context.Context, articleID int64, newsArticle *CreatorArticleRequestPayload) error {
	return nil
}
