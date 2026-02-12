package creator

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"com.martdev.newsify/internal/util"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var testDB *sql.DB

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("newsify_newsarticle_test"),
		postgres.WithUsername("testAdmin"),
		postgres.WithPassword("testPassword"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("failed to start container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %v", err)
	}

	log.Printf("connection string is %s", connStr)

	testDB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to connect to db:  %v", err)
	}

	migrationsPath := filepath.Join("..", "..", "..", "cmd", "migrate", "migrations")

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("failed to set dialect: %v", err)
	}

	if err := goose.Up(testDB, migrationsPath); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	code := m.Run()

	if err := pgContainer.Terminate(ctx); err != nil {
		log.Printf("failed to terminal container: %v", err)
	}

	os.Exit(code)
}

func setupTest(t *testing.T) {
	_, err := testDB.Exec("TRUNCATE TABLE news_article CASCADE")
	require.NoError(t, err)
}

// write test for other functions
func TestNewsArticleStore(t *testing.T) {
	store := NewsArticleStore{DB: testDB}

	t.Run("should create news article successfully", func(t *testing.T) {
		setupTest(t)
		newsArticle := &NewsArticle{
			Title:     "title1",
			Content:   "content1",
			CreatorID: 1,
		}

		err := store.CreateNewsArticle(t.Context(), newsArticle)
		require.NoError(t, err)
		require.NotEqual(t, 0, newsArticle.ID)

		savedNewsArticle, err := store.GetNewsArticleById(t.Context(), 1, newsArticle.ID)
		require.NoError(t, err)
		assert.Equal(t, newsArticle.Title, savedNewsArticle.Title)
		assert.Equal(t, newsArticle.Content, savedNewsArticle.Content)
	})

	t.Run("should not allow 2 articles with the same titles to be created", func(t *testing.T) {
		setupTest(t)
		newsArticle := &NewsArticle{
			Title:     "title1",
			Content:   "content1",
			CreatorID: 1,
		}

		newsArticle2 := &NewsArticle{
			Title:     "title1",
			Content:   "content1",
			CreatorID: 1,
		}

		err := store.CreateNewsArticle(t.Context(), newsArticle)
		require.NoError(t, err)
		require.NotEqual(t, 0, newsArticle.ID)

		err = store.CreateNewsArticle(t.Context(), newsArticle2)
		require.Error(t, err)

		savedNewsArticle, err := store.GetNewsArticleById(t.Context(), 1, newsArticle.ID)
		require.NoError(t, err)
		assert.Equal(t, newsArticle.Title, savedNewsArticle.Title)
		assert.Equal(t, newsArticle.Content, savedNewsArticle.Content)

		_, err = store.GetNewsArticleById(t.Context(), 1, newsArticle2.ID)
		assert.Error(t, err)
	})

	t.Run("get all news article by creator", func(t *testing.T) {
		setupTest(t)

		pagination := util.PaginatedPostQuery{
			Limit:  3,
			Offset: 0,
		}
		newsArticle := &NewsArticle{
			Title:     "title1",
			Content:   "content1",
			CreatorID: 1,
		}

		newsArticle2 := &NewsArticle{
			Title:     "title2",
			Content:   "content2",
			CreatorID: 1,
		}

		newsArticle3 := &NewsArticle{
			Title:     "title3",
			Content:   "content3",
			CreatorID: 2,
		}

		newsArticles := append([]NewsArticle{}, *newsArticle, *newsArticle2, *newsArticle3)

		for _, na := range newsArticles {
			err := store.CreateNewsArticle(t.Context(), &na)
			require.NoError(t, err)
			require.NotEqual(t, 0, na.ID)
		}

		newsArticlesByCreator, err := store.GetAllNewsArticleByCreator(t.Context(), 1, pagination)
		require.NoError(t, err)
		require.Len(t, newsArticlesByCreator, 2)
		require.Equal(t, newsArticle.Title, newsArticlesByCreator[0].Title)
		require.Equal(t, newsArticle2.Title, newsArticlesByCreator[1].Title)

		newsArticlesByCreator2, err := store.GetAllNewsArticleByCreator(t.Context(), 2, pagination)
		require.NoError(t, err)
		require.Len(t, newsArticlesByCreator2, 1)
		require.Equal(t, newsArticle3.Title, newsArticlesByCreator2[0].Title)
	})

	t.Run("delete news article created", func(t *testing.T) {
		setupTest(t)

		newsArticle := &NewsArticle{
			Title:     "title11",
			Content:   "content11",
			CreatorID: 11,
		}

		err := store.CreateNewsArticle(t.Context(), newsArticle)
		require.NoError(t, err)

		err = store.DeleteNewsArticle(t.Context(), 11, newsArticle.ID)
		require.NoError(t, err)

		na, err := store.GetNewsArticleById(t.Context(), 11, newsArticle.ID)
		assert.Error(t, err)
		assert.Nil(t, na)
	})

	t.Run("update news article", func(t *testing.T) {
		setupTest(t)

		newsArticle := &NewsArticle{
			Title:     "title12",
			Content:   "content12",
			CreatorID: 12,
		}

		err := store.CreateNewsArticle(t.Context(), newsArticle)
		require.NoError(t, err)

		na, err := store.GetNewsArticleById(t.Context(), 12, newsArticle.ID)
		require.NoError(t, err)
		require.Equal(t, newsArticle.Title, na.Title)

		modifiedNewsArticle := &NewsArticle{
			ID:      newsArticle.ID,
			Title:   "title13",
			Content: "title13",
		}

		err = store.UpdateNewsArticle(t.Context(), 12, modifiedNewsArticle)
		require.NoError(t, err)

		modifiedNA, err := store.GetNewsArticleById(t.Context(), 12, modifiedNewsArticle.ID)
		require.NoError(t, err)
		assert.Equal(t, modifiedNewsArticle.Title, modifiedNA.Title)
	})
}
