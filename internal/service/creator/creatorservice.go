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
	ca := &creator.CreatorArticle{
		Title:     creatorArticle.Title,
		Content:   creatorArticle.Content,
		CreatorID: creatorArticle.CreatorID,
	}

	if err := c.store.CreateNewsArticle(ctx, ca); err != nil {
		return err
	}

	return nil
}

func (c *CreatorArticleService) GetNewsArticleById(ctx context.Context, articleID int64, creatorID int64) (*CreatorArticleResponsePayload, error) {

	ca, err := c.store.GetNewsArticleById(ctx, creatorID, articleID)
	if err != nil {
		return nil, err
	}
	response := &CreatorArticleResponsePayload{
		Title:     ca.Title,
		Content:   ca.Content,
		CreatedAt: ca.CreatedAt,
	}
	return response, nil
}

func (c *CreatorArticleService) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]CreatorArticleResponsePayload, error) {
	cas, err := c.store.GetAllNewsArticleByCreator(ctx, creatorID, pagination)
	if err != nil {
		return make([]CreatorArticleResponsePayload, 0), nil
	}
	response := []CreatorArticleResponsePayload{}

	for _, ca := range cas {
		creatorArticle := CreatorArticleResponsePayload{
			ID:    ca.ID,
			Title: ca.Title,
		}
		response = append(response, creatorArticle)
	}
	return response, nil
}

func (c *CreatorArticleService) DeleteNewsArticle(ctx context.Context, articleID int64, creatorID int64) error {
	if err := c.store.DeleteNewsArticle(ctx, creatorID, articleID); err != nil {
		return err
	}
	return nil
}

func (c *CreatorArticleService) UpdateNewsArticle(ctx context.Context, articleID int64, newsArticle *CreatorArticleRequestPayload) error {
	ca := &creator.CreatorArticle{
		ID:      articleID,
		Title:   newsArticle.Title,
		Content: newsArticle.Content,
	}
	if err := c.store.UpdateNewsArticle(ctx, ca); err != nil {
		return err
	}
	return nil
}
