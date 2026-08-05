package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/LaplaceOrange/fly/internal/config"
	"github.com/LaplaceOrange/fly/internal/cpoauth"
	"github.com/LaplaceOrange/fly/internal/realtime"
	"github.com/LaplaceOrange/fly/internal/store"
	"github.com/LaplaceOrange/fly/internal/turnstile"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

const (
	sessionCookieName = "fly_session"
	oauthCookieName   = "fly_oauth"
)

type OAuthClient interface {
	ExchangeAndFetchUser(context.Context, cpoauth.TokenRequest) (cpoauth.UserInfo, error)
}

type TurnstileClient interface {
	Verify(context.Context, string, string, string) error
}

type Dependencies struct {
	Config     config.Config
	Store      *store.Store
	CPOAuth    OAuthClient
	Turnstile  TurnstileClient
	Hub        *realtime.Hub
	FrontendFS fs.FS
	Logger     *slog.Logger
}

type Server struct {
	cfg        config.Config
	store      *store.Store
	cpoauth    OAuthClient
	turnstile  TurnstileClient
	hub        *realtime.Hub
	frontendFS fs.FS
	logger     *slog.Logger
	handler    http.Handler
}

func New(deps Dependencies) *Server {
	frontend, err := fs.Sub(deps.FrontendFS, "web/dist")
	if err != nil {
		frontend = deps.FrontendFS
	}
	s := &Server{
		cfg: deps.Config, store: deps.Store, cpoauth: deps.CPOAuth, turnstile: deps.Turnstile,
		hub: deps.Hub, frontendFS: frontend, logger: deps.Logger,
	}
	s.handler = s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(chimiddleware.Recoverer)
	router.Use(s.securityHeaders)
	router.Use(s.logRequests)

	router.Get("/healthz", s.health)
	router.Route("/api", func(api chi.Router) {
		api.Use(noStore)
		api.Get("/public-config", s.publicConfig)
		api.Get("/dashboard", s.dashboard)
		api.Get("/users", s.users)
		api.Get("/me", s.me)
		api.Get("/realtime", s.realtime)
		api.Get("/shares/{shareID}", s.getShare)
		api.Get("/share-recipients", s.shareRecipients)
		api.Get("/share-recipients/{userID}/keys", s.recipientExchangeKeys)
		api.Get("/prekeys", s.prekeyStatus)
		api.Get("/devices", s.devices)
		api.Route("/auth", func(auth chi.Router) {
			auth.Get("/login", s.authLogin)
			auth.Get("/callback", s.authCallback)
			auth.With(s.sameOrigin).Post("/logout", s.authLogout)
		})
		api.With(s.sameOrigin).Post("/flights", s.createFlight)
		api.With(s.sameOrigin).Post("/keys", s.registerSigningKey)
		api.With(s.sameOrigin).Post("/exchange-keys", s.registerExchangeKey)
		api.With(s.sameOrigin).Post("/prekeys", s.registerPrekeys)
		api.With(s.sameOrigin).Post("/share-recipients/{userID}/prekeys/claim", s.claimRecipientPrekeys)
		api.With(s.sameOrigin).Post("/devices/{exchangeKeyID}/revoke", s.revokeDevice)
		api.With(s.sameOrigin).Post("/shares", s.createShare)
	})
	router.NotFound(s.serveFrontend)
	return router
}

func (s *Server) publicConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"siteName":         s.cfg.SiteName,
		"turnstileSiteKey": s.cfg.TurnstileSiteKey,
		"rateLimitMinutes": int(s.cfg.TakeoffRateLimit / time.Minute),
		"timezone":         s.cfg.Location.String(),
		"shareTTLHours":    int(s.cfg.ShareTTL / time.Hour),
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "数据库暂时不可用", 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	data, err := s.store.Dashboard(r.Context(), rangeName, time.Now())
	if err != nil {
		if strings.Contains(err.Error(), "range must") {
			writeError(w, http.StatusBadRequest, "invalid_range", err.Error(), 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	limit := 30
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit 必须是整数", 0)
			return
		}
		limit = parsed
	}
	page, err := s.store.Users(r.Context(), r.URL.Query().Get("cursor"), r.URL.Query().Get("sort"), limit, time.Now(), s.cfg.TakeoffRateLimit)
	if err != nil {
		if strings.Contains(err.Error(), "cursor") || strings.Contains(err.Error(), "sort") {
			writeError(w, http.StatusBadRequest, "invalid_query", err.Error(), 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	status := s.store.UserStatus(r.Context(), user, time.Now(), s.cfg.TakeoffRateLimit)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          status.User,
		"canTakeoff":    status.CanTakeoff,
		"nextAllowedAt": status.NextAllowedAt,
	})
}

func (s *Server) realtime(w http.ResponseWriter, r *http.Request) {
	revision, err := s.store.Revision(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.hub.ServeHTTP(w, r, revision)
}

func (s *Server) createFlight(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先使用 CPOAuth 登录", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var request struct {
		TurnstileToken string `json:"turnstileToken"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求内容无效", 0)
		return
	}
	if strings.TrimSpace(request.TurnstileToken) == "" || len(request.TurnstileToken) > 4096 {
		writeError(w, http.StatusBadRequest, "invalid_turnstile_token", "人机验证 token 无效", 0)
		return
	}
	idempotencyKey, err := randomToken(16)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.turnstile.Verify(r.Context(), request.TurnstileToken, s.clientIP(r), idempotencyKey); err != nil {
		if turnstile.IsInvalid(err) {
			writeError(w, http.StatusForbidden, "turnstile_failed", "人机验证失败，请刷新后重试", 0)
			return
		}
		s.logger.Warn("turnstile upstream failure", "request_id", chimiddleware.GetReqID(r.Context()), "error", err)
		writeError(w, http.StatusBadGateway, "turnstile_unavailable", "人机验证服务暂时不可用", 0)
		return
	}
	flight, nextAllowedAt, err := s.store.CreateFlight(r.Context(), user.ID, time.Now(), s.cfg.TakeoffRateLimit)
	if err != nil {
		var limited *store.RateLimitError
		if errors.As(err, &limited) {
			retry := max(1, int(time.Until(limited.NextAllowedAt).Seconds()+0.999))
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": map[string]any{
					"code": "rate_limited", "message": "起飞过于频繁，请稍后再试", "retryAfterSeconds": retry,
					"nextAllowedAt": limited.NextAllowedAt,
				},
			})
			return
		}
		s.internalError(w, r, err)
		return
	}
	event := realtime.Event{Type: "flight.created", Revision: flight.ID, Flight: flight}
	s.hub.Broadcast(event)
	writeJSON(w, http.StatusCreated, map[string]any{"flight": flight, "nextAllowedAt": nextAllowedAt})
}

func (s *Server) currentUser(r *http.Request) (store.User, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return store.User{}, false
	}
	user, err := s.store.UserBySession(r.Context(), store.SessionHash(cookie.Value), time.Now())
	if err != nil {
		return store.User{}, false
	}
	return user, true
}

func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(parsed.Scheme, s.cfg.PublicBaseURL.Scheme) || !strings.EqualFold(parsed.Host, s.cfg.PublicBaseURL.Host) {
				writeError(w, http.StatusForbidden, "origin_rejected", "请求来源无效", 0)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil || !s.isTrustedProxy(peer) {
		return host
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		candidate, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			continue
		}
		if !s.isTrustedProxy(candidate) {
			return candidate.String()
		}
	}
	if realIP, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return realIP.String()
	}
	return peer.String()
}

func (s *Server) isTrustedProxy(address netip.Addr) bool {
	for _, prefix := range s.cfg.TrustedProxyPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/turnstile-frame.html" {
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		} else {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.URL.Path == "/turnstile-frame.html" {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'unsafe-inline'; connect-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' ws: wss:; frame-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		}
		if s.cfg.PublicBaseURL.Scheme == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		if !strings.HasPrefix(r.URL.Path, "/healthz") {
			s.logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds(), "request_id", chimiddleware.GetReqID(r.Context()))
		}
	})
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) serveFrontend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	requested := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if requested == "." || requested == "" {
		requested = "index.html"
	}
	data, err := fs.ReadFile(s.frontendFS, requested)
	if err != nil {
		requested = "index.html"
		data, err = fs.ReadFile(s.frontendFS, requested)
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "frontend_not_built", "前端尚未构建，请先运行 npm --prefix web run build", 0)
		return
	}
	if strings.HasPrefix(requested, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if contentType := mime.TypeByExtension(path.Ext(requested)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, requested, time.Time{}, bytes.NewReader(data))
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "request_id", chimiddleware.GetReqID(r.Context()), "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "服务器内部错误", 0)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string, retryAfter int) {
	errorBody := map[string]any{"code": code, "message": message}
	if retryAfter > 0 {
		errorBody["retryAfterSeconds"] = retryAfter
	}
	writeJSON(w, status, map[string]any{"error": errorBody})
}

func randomToken(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) sign(payload []byte) string {
	mac := hmac.New(sha256.New, s.cfg.SessionSecret)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) encodeSigned(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + s.sign([]byte(encoded)), nil
}

func (s *Server) decodeSigned(raw string, target any) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.sign([]byte(parts[0])))) {
		return errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, target)
}

func (s *Server) callbackURL() string {
	return s.cfg.PublicBaseURL.ResolveReference(&url.URL{Path: "/api/auth/callback"}).String()
}

func (s *Server) cookieSecure() bool { return s.cfg.PublicBaseURL.Scheme == "https" }
