package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaplaceOrange/fly/internal/cpoauth"
	"github.com/LaplaceOrange/fly/internal/store"
)

type oauthTransaction struct {
	State        string `json:"state"`
	CodeVerifier string `json:"codeVerifier"`
	ReturnTo     string `json:"returnTo"`
	ExpiresAt    int64  `json:"expiresAt"`
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	state, err := randomToken(32)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	verifier, err := randomToken(64)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	transaction := oauthTransaction{State: state, CodeVerifier: verifier, ReturnTo: returnTo, ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
	encoded, err := s.encodeSigned(transaction)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oauthCookieName, Value: encoded, Path: "/api/auth", MaxAge: 600,
		HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode,
	})

	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	authorize, err := url.Parse(s.cfg.CPOAuthAuthorizeURL)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	query := authorize.Query()
	query.Set("response_type", "code")
	query.Set("client_id", s.cfg.CPOAuthClientID)
	query.Set("redirect_uri", s.callbackURL())
	query.Set("scope", s.cfg.CPOAuthScopes)
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	authorize.RawQuery = query.Encode()
	http.Redirect(w, r, authorize.String(), http.StatusFound)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	if oauthError := r.URL.Query().Get("error"); oauthError != "" {
		http.Redirect(w, r, "/?auth_error="+url.QueryEscape(oauthError), http.StatusFound)
		return
	}
	cookie, err := r.Cookie(oauthCookieName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "oauth_state_missing", "登录状态已过期，请重新登录", 0)
		return
	}
	clearCookie(w, oauthCookieName, "/api/auth", s.cookieSecure())
	var transaction oauthTransaction
	if err := s.decodeSigned(cookie.Value, &transaction); err != nil || transaction.ExpiresAt < time.Now().Unix() {
		writeError(w, http.StatusBadRequest, "oauth_state_invalid", "登录状态无效或已过期", 0)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" || !secureEqual(state, transaction.State) {
		writeError(w, http.StatusBadRequest, "oauth_callback_invalid", "登录回调参数无效", 0)
		return
	}
	userInfo, err := s.cpoauth.ExchangeAndFetchUser(r.Context(), cpoauth.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: s.callbackURL(),
		ClientID: s.cfg.CPOAuthClientID, ClientSecret: s.cfg.CPOAuthClientSecret, CodeVerifier: transaction.CodeVerifier,
	})
	if err != nil {
		s.logger.Warn("cpoauth login failed", "error", err)
		http.Redirect(w, r, "/?auth_error=cpoauth_failed", http.StatusFound)
		return
	}
	user, err := s.store.UpsertUser(r.Context(), store.User{
		ID: userInfo.Sub, Username: userInfo.Username, DisplayName: userInfo.DisplayName, AvatarURL: userInfo.AvatarURL,
	}, time.Now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sessionToken, err := randomToken(32)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	expires := now.Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(r.Context(), store.SessionHash(sessionToken), user.ID, now, expires); err != nil {
		s.internalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: sessionToken, Path: "/", Expires: expires, MaxAge: int(s.cfg.SessionTTL.Seconds()),
		HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, safeReturnTo(transaction.ReturnTo), http.StatusFound)
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		_ = s.store.DeleteSession(r.Context(), store.SessionHash(cookie.Value))
	}
	clearCookie(w, sessionCookieName, "/", s.cookieSecure())
	w.WriteHeader(http.StatusNoContent)
}

func safeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	return value
}

func clearCookie(w http.ResponseWriter, name, cookiePath string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: cookiePath, MaxAge: -1, Expires: time.Unix(1, 0),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}
