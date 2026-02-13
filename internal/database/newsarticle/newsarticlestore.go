package creator

import (
	"context"
	"database/sql"
	"errors"

	"com.martdev.newsify/internal/util"
)

type NewsArticle struct {
	ID        int64
	Title     string
	Content   string
	CreatorID int64
	CreatedAt string
}

type NewsArticleStorer interface {
	CreateNewsArticle(context.Context, *NewsArticle) error
	GetNewsArticleById(ctx context.Context, creatorID int64, articleID int64) (*NewsArticle, error)
	GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]NewsArticle, error)
	DeleteNewsArticle(ctx context.Context, creatorID int64, articleID int64) error
	UpdateNewsArticle(ctx context.Context, newsArticle *NewsArticle) error
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
		SELECT na.title, na.content, na.created_at FROM news_article na WHERE na.creator_id = $1 AND na.id = $2 ORDER BY na.created_at DESC
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	var news NewsArticle
	if err := na.DB.QueryRowContext(ctx, query, creatorID, articleID).Scan(
		&news.Title,
		&news.Content,
		&news.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &news, nil
}

func (na *NewsArticleStore) GetAllNewsArticleByCreator(ctx context.Context, creatorID int64, pagination util.PaginatedPostQuery) ([]NewsArticle, error) {
	query := "SELECT id, title FROM news_article na WHERE na.creator_id = $1 ORDER BY na.created_at LIMIT $2 OFFSET $3"

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	rows, err := na.DB.QueryContext(ctx, query, creatorID, pagination.Limit, pagination.Offset)
	if err != nil {
		return nil, err
	}

	var newsArticles []NewsArticle

	for rows.Next() {
		var newsArticle NewsArticle
		if err := rows.Scan(
			&newsArticle.ID,
			&newsArticle.Title,
		); err != nil {
			return nil, err
		}

		newsArticles = append(newsArticles, newsArticle)
	}
	return newsArticles, nil
}

func (na *NewsArticleStore) DeleteNewsArticle(ctx context.Context, creatorID int64, articleID int64) error {
	query := `
		DELETE FROM news_article na WHERE na.id = $1 AND na.creator_id = $2
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := na.DB.ExecContext(ctx, query, articleID, creatorID)
	if err != nil {
		return err
	}
	return nil
}

func (na *NewsArticleStore) UpdateNewsArticle(ctx context.Context, newsArticle *NewsArticle) error {
	query := `
		UPDATE news_article SET title = $1, content = $2 WHERE id = $3 RETURNING id
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	if err := na.DB.QueryRowContext(
		ctx, query, newsArticle.Title, newsArticle.Content, newsArticle.ID,
	).Scan(&newsArticle.ID); err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return util.ErrorConflict
		default:
			return err
		}
	}

	return nil
}
