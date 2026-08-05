package store

import (
	"errors"
	"time"
)

var (
	ErrDeviceKeyLimit = errors.New("device key limit exceeded")
	ErrPrekeyLimit    = errors.New("prekey limit exceeded")
	ErrKeyRevoked     = errors.New("device key revoked")
	ErrPrekeyClaim    = errors.New("prekey claim invalid or expired")
)

type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"displayName"`
	AvatarURL    string     `json:"avatarUrl"`
	TotalFlights int64      `json:"totalFlights"`
	LastFlightAt *time.Time `json:"lastFlightAt"`
}

type UserStatus struct {
	User
	CanTakeoff    bool       `json:"canTakeoff"`
	NextAllowedAt *time.Time `json:"nextAllowedAt"`
}

type Flight struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	User      User      `json:"user"`
}

type Summary struct {
	TotalFlights int64      `json:"totalFlights"`
	RangeFlights int64      `json:"rangeFlights"`
	TotalUsers   int64      `json:"totalUsers"`
	ActiveUsers  int64      `json:"activeUsers"`
	LastFlightAt *time.Time `json:"lastFlightAt"`
}

type TrendPoint struct {
	BucketStart time.Time `json:"bucketStart"`
	Count       int64     `json:"count"`
}

type HeatCell struct {
	Weekday int   `json:"weekday"`
	Hour    int   `json:"hour"`
	Count   int64 `json:"count"`
}

type LeaderboardEntry struct {
	Rank         int        `json:"rank"`
	User         User       `json:"user"`
	FlightCount  int64      `json:"flightCount"`
	LastFlightAt *time.Time `json:"lastFlightAt"`
}

type Dashboard struct {
	GeneratedAt   time.Time          `json:"generatedAt"`
	Revision      int64              `json:"revision"`
	Range         string             `json:"range"`
	Summary       Summary            `json:"summary"`
	Trend         []TrendPoint       `json:"trend"`
	Leaderboard   []LeaderboardEntry `json:"leaderboard"`
	Heatmap       []HeatCell         `json:"heatmap"`
	RecentFlights []Flight           `json:"recentFlights"`
}

type UsersPage struct {
	Users      []UserStatus `json:"users"`
	NextCursor string       `json:"nextCursor,omitempty"`
}

type RateLimitError struct {
	NextAllowedAt time.Time
}

type SigningKey struct {
	ID          string     `json:"id"`
	UserID      string     `json:"-"`
	Algorithm   string     `json:"algorithm"`
	PublicJWK   string     `json:"publicJwk"`
	Fingerprint string     `json:"fingerprint"`
	DeviceLabel string     `json:"deviceLabel,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	RevokedAt   *time.Time `json:"revokedAt,omitempty"`
}

type ExchangeKey struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"-"`
	PublicJWK          string     `json:"publicJwk"`
	Fingerprint        string     `json:"fingerprint"`
	SigningKeyID       string     `json:"signingKeyId"`
	BindingVersion     int        `json:"bindingVersion"`
	BindingSignature   string     `json:"bindingSignature"`
	SigningPublicJWK   string     `json:"signingPublicJwk,omitempty"`
	SigningFingerprint string     `json:"signingFingerprint,omitempty"`
	DeviceLabel        string     `json:"deviceLabel,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	LastSeenAt         time.Time  `json:"lastSeenAt"`
	RevokedAt          *time.Time `json:"revokedAt,omitempty"`
}

type OneTimePrekey struct {
	ID                  string    `json:"keyId"`
	UserID              string    `json:"-"`
	ExchangeKeyID       string    `json:"exchangeKeyId"`
	SigningKeyID        string    `json:"signingKeyId"`
	PublicJWK           string    `json:"-"`
	Fingerprint         string    `json:"fingerprint"`
	BindingVersion      int       `json:"bindingVersion"`
	BindingSignature    string    `json:"bindingSignature"`
	ExchangePublicJWK   string    `json:"-"`
	ExchangeFingerprint string    `json:"exchangeFingerprint"`
	ExchangeBinding     string    `json:"exchangeBindingSignature"`
	SigningPublicJWK    string    `json:"-"`
	SigningFingerprint  string    `json:"signingFingerprint"`
	DeviceLabel         string    `json:"deviceLabel,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
}

type Device struct {
	ExchangeKeyID       string     `json:"exchangeKeyId"`
	SigningKeyID        string     `json:"signingKeyId"`
	DeviceLabel         string     `json:"deviceLabel"`
	ExchangeFingerprint string     `json:"exchangeFingerprint"`
	SigningFingerprint  string     `json:"signingFingerprint"`
	CreatedAt           time.Time  `json:"createdAt"`
	LastSeenAt          time.Time  `json:"lastSeenAt"`
	RevokedAt           *time.Time `json:"revokedAt,omitempty"`
}

type ShareRecipient struct {
	User
	DeviceCount int `json:"deviceCount"`
}

type Share struct {
	ID                 string    `json:"id"`
	Encrypted          bool      `json:"encrypted"`
	Payload            string    `json:"payload"`
	IV                 string    `json:"iv"`
	Signature          string    `json:"signature"`
	SignatureVersion   int       `json:"signatureVersion"`
	CryptoSuite        string    `json:"cryptoSuite"`
	RecipientUserID    string    `json:"recipientUserId,omitempty"`
	EphemeralPublicJWK string    `json:"ephemeralPublicJwk,omitempty"`
	KeyEnvelopes       string    `json:"keyEnvelopes,omitempty"`
	CreatedAt          time.Time `json:"createdAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
	SignedExpiresAt    string    `json:"-"`
	Signer             User      `json:"signer"`
	KeyID              string    `json:"keyId"`
	SigningAlgorithm   string    `json:"signingAlgorithm"`
	PublicJWK          string    `json:"publicJwk"`
	Fingerprint        string    `json:"fingerprint"`
}

func (e *RateLimitError) Error() string { return "takeoff rate limit exceeded" }
