package util

import (
	"net/http"

	"go.uber.org/zap"
)

func InternalServerErrorResponse(w http.ResponseWriter, r *http.Request, err error, logger *zap.SugaredLogger) {
	logger.Errorw("internal error", "method", r.Method, "path", r.URL.Path, "error", err.Error())
	writeJSONError(w, http.StatusInternalServerError, "the server encountered a problem")
}

func BadRequestErrorResponse(w http.ResponseWriter, r *http.Request, err error, logger *zap.SugaredLogger) {
	logWarning("bad request error", r, err, logger)
	writeJSONError(w, http.StatusBadRequest, err.Error())
}

func NotFoundErrorResponse(w http.ResponseWriter, r *http.Request, err error, logger *zap.SugaredLogger) {
	logWarning("not found error", r, err, logger)
	writeJSONError(w, http.StatusNotFound, "not found")
}

func UnauthorizedErrorResponse(w http.ResponseWriter, r *http.Request, err error, logger *zap.SugaredLogger) {
	logWarning("unauthorized error", r, err, logger)
	writeJSONError(w, http.StatusUnauthorized, "unauthorized")
}

func RateLimitExceededErrorResponse(w http.ResponseWriter, r *http.Request, retryAfter string, logger *zap.SugaredLogger) {
	logger.Warnw("rate limit exceeded, retry after: "+retryAfter, "method", r.Method, "path", r.URL.Path)
	w.Header().Set("Retry-After", retryAfter)

	writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded, retry after: "+retryAfter)
}

func logWarning(message string, r *http.Request, err error, logger *zap.SugaredLogger) {
	logger.Warnf(message, "method", r.Method, "path", r.URL.Path, "error", err.Error())
}
