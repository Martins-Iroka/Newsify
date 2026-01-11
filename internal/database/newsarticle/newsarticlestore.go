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
	query := `
		INSERT INTO news_article (title, content, creator_id) VALUES ($1, $2, $3) RETURNING id
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	if err := na.DB.QueryRowContext(ctx, query, newsArticle.Title, newsArticle.Content, newsArticle.CreatorID).Scan(
		&newsArticle.ID,
	); err != nil {
		return err
	}
	return nil
}

func (na *NewsArticleStore) GetNewsArticleById(ctx context.Context, creatorID int64, articleID int64) (*NewsArticle, error) {
	query := `
		SELECT na.title, na.content, na.created_at FROM news_article na WHERE na.id = $1 AND na.creator_id = $2 ORDER BY na.created_at DESC
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	var news NewsArticle
	if err := na.DB.QueryRowContext(ctx, query, articleID, creatorID).Scan(
		&news.Title,
		&news.Content,
		&news.CreatorID,
	); err != nil {
		return nil, err
	}
	return &news, nil
}

func (na *NewsArticleStore) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]NewsArticle, error) {
	return []NewsArticle{}, nil
}

func (na *NewsArticleStore) DeleteNewsArticle(ctx context.Context, creatorID int64, articleID int64) error {
	query := `
		DELETE FROM news_article WHERE id = $1 AND creator_id = $2
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := na.DB.ExecContext(ctx, query, articleID, creatorID)
	if err != nil {
		return err
	}
	return nil
}

func (na *NewsArticle) UpdateNewsArticle(ctx context.Context, creatorID int64, newsArticle *NewsArticle) (*NewsArticle, error) {
	return nil, nil
}
