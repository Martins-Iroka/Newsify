package creator

import (
	"context"
	"database/sql"

	"com.martdev.newsify/internal/util"
)

type NewsArticle struct {
	ID        int64
	Title     string
	Content   string
	CreatorID int64
}

type NewsArticleStorer interface {
	CreateNewsArticle(context.Context, *NewsArticle) error
	GetNewsArticleById(ctx context.Context, creatorID int64, articleID int64) (*NewsArticle, error)
	GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]NewsArticle, error)
	DeleteNewsArticle(ctx context.Context, creatorID int64, articleID int64) error
	UpdateNewsArticle(ctx context.Context, creatorID int64, newsArticle *NewsArticle) (*NewsArticle, error)
}

type NewsArticleStore struct {
	DB *sql.DB
}

func (na *NewsArticleStore) CreateNewsArticle(ctx context.Context, newsArticle *NewsArticle) error {
	return nil
}

func (na *NewsArticleStore) GetNewsArticleById(ctx context.Context, creatorID int64, article int64) (*NewsArticle, error) {
	return nil, nil
}

func (na *NewsArticleStore) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]NewsArticle, error) {
	return []NewsArticle{}, nil
}

func (na *NewsArticleStore) DeleteNewsArticle(ctx context.Context, creatorID int64, articleID int64) error {
	return nil
}

func (na *NewsArticle) UpdateNewsArticle(ctx context.Context, creatorID int64, newsArticle *NewsArticle) (*NewsArticle, error) {
	return nil, nil
}
