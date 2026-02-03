package user

import (
	"errors"
	"net/http"

	_ "com.martdev.newsify/docs"
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

// RegisterUserHandler godoc
//
//	@summary	Registers a user
//	@tags		authentication
//	@accept		json
//	@produce	json
//	@param		payload	body		user.RegisterUserRequest	true	"User credentials"
//	@success	201		{object}	user.RegisterUserResponse	"User registration token"
//	@failure	400		{object}	util.ErrorResponse
//	@failure	500		{object}	util.ErrorResponse
//	@router		/authentication/register [post]
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

// VerifyUserHandler godoc
//
//	@summary	User verification
//	@tags		authentication
//	@accept		json
//	@produce	json
//	@param		payload	body	user.VerifyUserRequest	true	"User verification credentials"
//	@success	204
//	@failure	400	{object}	util.ErrorResponse
//	@failure	500	{object}	util.ErrorResponse
//	@router		/authentication/verify [post]
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

// LoginUserHandler godoc
//
//	@summary	User login
//	@tags		authentication
//	@accept		json
//	@produce	json
//	@param		payload	body		user.LoginUserRequest	true	"User login credentials"
//	@success	200		{string}	Token					"User token"
//	@failure	400		{object}	util.ErrorResponse
//	@failure	500		{object}	util.ErrorResponse
//	@router		/authentication/login [post]
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

// RefreshTokenHandler godoc
//
//	@Summary	Refresh access token
//	@tags		authentication
//	@accept		json
//	@produce	json
//	@param		payload	body		user.RefreshTokenRequest	true	"Refresh token"
//	@success	200		{object}	user.RefreshTokenResponse	"New access token"
//	@failure	400		{object}	util.ErrorResponse
//	@failure	401		{object}	util.ErrorResponse
//	@failure	500		{object}	util.ErrorResponse
//	@router		/authentication/refresh [post]
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

// LogoutHandler godoc
//
//	@summary	Logout user
//	@tags		authentication
//	@accept		json
//	@produce	json
//	@param		payload	body	string	true	"Refresh token to revoke"
//	@success	204		"No content"
//	@failure	500		{object}	util.ErrorResponse
//	@router		/authentication/{refreshToken}/logout [post]
func (h *Handler) logoutUserHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := chi.URLParam(r, "refreshToken")

	if err := h.service.LogoutUser(r.Context(), refreshToken); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResendOTPHandler godoc
//
//	@summary	Resend OTP
//	@tags		authentication
//	@accept		json
//	@produce	json
//	@param		payload	body		user.ResendOTPRequest	true	"Resend OTP"
//	@success	200		{object}	user.ResendOTPResponse	"OTP sent"
//	@failure	400		{object}	util.ErrorResponse
//	@failure	500		{object}	util.ErrorResponse
//	@router		/authentication/resendOTP [post]
func (h *Handler) resendOTPHandler(w http.ResponseWriter, r *http.Request) {
	var payload userservice.ResendOTPRequest

	if err := util.ReadJSON(w, r, &payload); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if err := util.Validate.Struct(payload); err != nil {
		util.BadRequestErrorResponse(w, r, err, h.logger)
		return
	}

	if response, err := h.service.ResendOTP(r.Context(), payload); err != nil {
		util.InternalServerErrorResponse(w, r, err, h.logger)
	} else {
		if err := util.JSONResponse(w, http.StatusOK, response); err != nil {
			util.InternalServerErrorResponse(w, r, err, h.logger)
		}
	}
}
