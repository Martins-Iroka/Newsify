package user

import (
	"errors"
	"net/http"

	userservice "com.martdev.newsify/internal/service/user"
	"com.martdev.newsify/internal/util"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Handler struct {
	service userservice.UserService
	logger  *zap.SugaredLogger
}

func NewHandler(service userservice.UserService, logger *zap.SugaredLogger) *Handler {
	return &Handler{service: service, logger: logger}
}

func (h *Handler) registerUserHandler(w http.ResponseWriter, r *http.Request) {
	var req userservice.RegisterUserRequest

	if err := util.ReadJSON(w, r, &req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	verificationToken := uuid.New().String()

	tokenResponse, err := h.service.RegisterUser(r.Context(), req, verificationToken)
	if err != nil {
		switch err {
		case util.ErrorDuplicateEmail, util.ErrorDuplicateUsername:
			util.BadRequestErrorResponse(w, r, err, h.logger)
		default:
			util.InternalServerErrorResponse(w, r, err, h.logger)
		}
		return
	}

	if err := util.JSONResponse(w, http.StatusCreated, tokenResponse); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
	}
}

func (h *Handler) verifyUserHandler(w http.ResponseWriter, r *http.Request) {
	var req userservice.VerifyUserRequest

	if err := util.ReadJSON(w, r, &req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	_, err := h.service.VerifyUser(r.Context(), req)
	if err != nil {
		switch err {
		case util.ErrorNotFound:
			util.NotFoundErrorResponse(w, r, err, h.logger)
		default:
			util.InternalServerErrorResponse(w, r, err, h.logger)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

func (h *Handler) loginUserHandler(w http.ResponseWriter, r *http.Request) {
	var req userservice.LoginUserRequest

	if err := util.ReadJSON(w, r, &req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	loginResponse, err := h.service.LoginUser(r.Context(), req)
	if err != nil {
		switch err {
		case util.ErrorNotFound:
			util.NotFoundErrorResponse(w, r, err, h.logger)
		default:
			util.InternalServerErrorResponse(w, r, err, h.logger)
		}
		return
	}

	if err := util.JSONResponse(w, http.StatusOK, loginResponse); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
	}
}

func (h *Handler) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req userservice.RefreshTokenRequest

	if err := util.ReadJSON(w, r, &req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(req); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	refreshTokenResponse, err := h.service.RefreshToken(r.Context(), req)
	if err != nil {
		switch err {
		case util.ErrorNotFound:
			util.UnauthorizedErrorResponse(w, r, errors.New("invalid or expired refresh token"), h.logger)
		default:
			util.InternalServerErrorResponse(w, r, err, h.logger)
		}
		return
	}

	if err := util.JSONResponse(w, http.StatusOK, refreshTokenResponse); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
	}
}

func (h *Handler) logoutUserHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := chi.URLParam(r, "refreshToken")

	if err := h.service.LogoutUser(r.Context(), refreshToken); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
