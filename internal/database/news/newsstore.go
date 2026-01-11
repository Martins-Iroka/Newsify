package creator

import "context"

type NewsArticle struct {
	ID        int64
	Title     string
	Content   string
	CreatorId int64
}

type NewsStorer interface {
	CreateNewsArticle(context.Context, *NewsArticle)
	GetNewsArticuleById(context.Context, int64)
}
