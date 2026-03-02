package util

import (
	"net/http"
	"strconv"
)

type PaginatedFeedQueryAPI struct {
	Limit  int `json:"limit" validate:"gte=1,lte=20"`
	Offset int `json:"offset" validate:"gte=0"`
}

func (p PaginatedFeedQueryAPI) Parse(r *http.Request) (PaginatedFeedQueryAPI, error) {
	qs := r.URL.Query()

	limit := qs.Get("limit")
	if limit != "" {
		l, err := strconv.Atoi(limit)
		if err != nil {
			return p, err
		}
		p.Limit = l
	}

	offset := qs.Get("offset")
	if offset != "" {
		off, err := strconv.Atoi(offset)
		if err != nil {
			return p, err
		}
		p.Offset = off
	}

	return p, nil
}
