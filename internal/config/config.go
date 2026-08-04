package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	SiteName                  string
	PublicBaseURL             *url.URL
	ListenAddr                string
	DatabasePath              string
	Location                  *time.Location
	CPOAuthClientID           string
	CPOAuthClientSecret       string
	CPOAuthAuthorizeURL       string
	CPOAuthTokenURL           string
	CPOAuthUserInfoURL        string
	CPOAuthScopes             string
	TurnstileSiteKey          string
	TurnstileSecretKey        string
	TurnstileExpectedHostname string
	TurnstileExpectedAction   string
	TakeoffRateLimit          time.Duration
	SessionSecret             []byte
	SessionTTL                time.Duration
	ShareTTL                  time.Duration
	TrustedProxyPrefixes      []netip.Prefix
}

func Load() (Config, error) {
	_ = godotenv.Load()
	baseURL, err := url.Parse(env("PUBLIC_BASE_URL", "http://localhost:8080"))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return Config{}, errors.New("PUBLIC_BASE_URL must be an absolute http(s) URL")
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return Config{}, errors.New("PUBLIC_BASE_URL must use http or https")
	}

	location, err := time.LoadLocation(env("APP_TIMEZONE", "Asia/Shanghai"))
	if err != nil {
		return Config{}, fmt.Errorf("APP_TIMEZONE: %w", err)
	}
	rateMinutes, err := positiveInt("TAKEOFF_RATE_LIMIT_MINUTES", 10)
	if err != nil {
		return Config{}, err
	}
	sessionHours, err := positiveInt("SESSION_TTL_HOURS", 720)
	if err != nil {
		return Config{}, err
	}
	shareHours, err := positiveInt("SHARE_TTL_HOURS", 168)
	if err != nil {
		return Config{}, err
	}

	secret := os.Getenv("SESSION_SECRET")
	if len(secret) < 32 {
		return Config{}, errors.New("SESSION_SECRET must contain at least 32 characters")
	}
	clientID := strings.TrimSpace(os.Getenv("CPOAUTH_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("CPOAUTH_CLIENT_SECRET"))
	turnstileSiteKey := strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY"))
	turnstileSecretKey := strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY"))
	if clientID == "" || clientSecret == "" {
		return Config{}, errors.New("CPOAUTH_CLIENT_ID and CPOAUTH_CLIENT_SECRET are required")
	}
	if turnstileSiteKey == "" || turnstileSecretKey == "" {
		return Config{}, errors.New("TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are required")
	}

	prefixes, err := parsePrefixes(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		SiteName:                  env("SITE_NAME", "中国人能飞"),
		PublicBaseURL:             baseURL,
		ListenAddr:                env("LISTEN_ADDR", ":8080"),
		DatabasePath:              env("DATABASE_PATH", "./data/fly.db"),
		Location:                  location,
		CPOAuthClientID:           clientID,
		CPOAuthClientSecret:       clientSecret,
		CPOAuthAuthorizeURL:       env("CPOAUTH_AUTHORIZE_URL", "https://www.cpoauth.com/api/oauth/authorize"),
		CPOAuthTokenURL:           env("CPOAUTH_TOKEN_URL", "https://www.cpoauth.com/api/oauth/token"),
		CPOAuthUserInfoURL:        env("CPOAUTH_USERINFO_URL", "https://www.cpoauth.com/api/oauth/userinfo"),
		CPOAuthScopes:             env("CPOAUTH_SCOPES", "openid profile"),
		TurnstileSiteKey:          turnstileSiteKey,
		TurnstileSecretKey:        turnstileSecretKey,
		TurnstileExpectedHostname: strings.TrimSpace(os.Getenv("TURNSTILE_EXPECTED_HOSTNAME")),
		TurnstileExpectedAction:   env("TURNSTILE_EXPECTED_ACTION", "turnstile-spin-v2"),
		TakeoffRateLimit:          time.Duration(rateMinutes) * time.Minute,
		SessionSecret:             []byte(secret),
		SessionTTL:                time.Duration(sessionHours) * time.Hour,
		ShareTTL:                  time.Duration(shareHours) * time.Hour,
		TrustedProxyPrefixes:      prefixes,
	}, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func positiveInt(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return value, nil
}

func parsePrefixes(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var prefixes []netip.Prefix
	for _, item := range strings.Split(raw, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS: %w", err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
