package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

func SessionHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) UpsertUser(ctx context.Context, user User, now time.Time) (User, error) {
	if user.ID == "" || user.Username == "" {
		return User{}, errors.New("cpoauth user id and username are required")
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	nowMS := now.UTC().UnixMilli()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO users (id, username, display_name, avatar_url, first_login_at, last_login_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  username = excluded.username,
  display_name = excluded.display_name,
  avatar_url = excluded.avatar_url,
  last_login_at = excluded.last_login_at,
  updated_at = excluded.updated_at`,
		user.ID, user.Username, user.DisplayName, user.AvatarURL, nowMS, nowMS, nowMS)
	if err != nil {
		return User{}, err
	}
	return s.UserByID(ctx, user.ID)
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, display_name, avatar_url, total_flights, last_flight_at FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) CreateSession(ctx context.Context, tokenHash, userID string, createdAt, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, createdAt.UTC().UnixMilli(), expiresAt.UTC().UnixMilli())
	return err
}

func (s *Store) UserBySession(ctx context.Context, tokenHash string, now time.Time) (User, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, now.UTC().UnixMilli())
	return scanUser(row)
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) Revision(ctx context.Context) (int64, error) {
	var revision int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM flights`).Scan(&revision)
	return revision, err
}

func (s *Store) CreateFlight(ctx context.Context, userID string, now time.Time, limit time.Duration) (Flight, time.Time, error) {
	s.flightMu.Lock()
	defer s.flightMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Flight{}, time.Time{}, err
	}
	defer tx.Rollback()

	now = now.UTC()
	cutoff := now.Add(-limit).UnixMilli()
	result, err := tx.ExecContext(ctx, `
INSERT INTO flights (user_id, created_at)
SELECT ?, ?
WHERE NOT EXISTS (
  SELECT 1 FROM flights WHERE user_id = ? AND created_at > ?
)`, userID, now.UnixMilli(), userID, cutoff)
	if err != nil {
		return Flight{}, time.Time{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Flight{}, time.Time{}, err
	}
	if changed == 0 {
		var lastMS int64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(created_at) FROM flights WHERE user_id = ?`, userID).Scan(&lastMS); err != nil {
			return Flight{}, time.Time{}, err
		}
		next := time.UnixMilli(lastMS).UTC().Add(limit)
		return Flight{}, next, &RateLimitError{NextAllowedAt: next}
	}

	flightID, err := result.LastInsertId()
	if err != nil {
		return Flight{}, time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET total_flights = total_flights + 1, last_flight_at = ?, updated_at = ? WHERE id = ?`, now.UnixMilli(), now.UnixMilli(), userID); err != nil {
		return Flight{}, time.Time{}, err
	}
	row := tx.QueryRowContext(ctx, `SELECT id, username, display_name, avatar_url, total_flights, last_flight_at FROM users WHERE id = ?`, userID)
	user, err := scanUser(row)
	if err != nil {
		return Flight{}, time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return Flight{}, time.Time{}, err
	}
	next := now.Add(limit)
	return Flight{ID: flightID, CreatedAt: now, User: user}, next, nil
}

func (s *Store) UserStatus(ctx context.Context, user User, now time.Time, limit time.Duration) UserStatus {
	status := UserStatus{User: user, CanTakeoff: true}
	if user.LastFlightAt != nil {
		next := user.LastFlightAt.Add(limit)
		status.NextAllowedAt = &next
		status.CanTakeoff = !now.Before(next)
	}
	return status
}

func (s *Store) Dashboard(ctx context.Context, rangeName string, now time.Time) (Dashboard, error) {
	now = now.UTC()
	start, err := rangeStart(rangeName, now)
	if err != nil {
		return Dashboard{}, err
	}
	dashboard := Dashboard{GeneratedAt: now, Range: rangeName}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(total_flights), 0), COALESCE(MAX(last_flight_at), 0) FROM users`).Scan(
		&dashboard.Summary.TotalUsers, &dashboard.Summary.TotalFlights, newNullTimeScanner(&dashboard.Summary.LastFlightAt)); err != nil {
		return Dashboard{}, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM flights`).Scan(&dashboard.Revision); err != nil {
		return Dashboard{}, err
	}
	if start == nil {
		dashboard.Summary.RangeFlights = dashboard.Summary.TotalFlights
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE total_flights > 0`).Scan(&dashboard.Summary.ActiveUsers); err != nil {
			return Dashboard{}, err
		}
	} else {
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT user_id) FROM flights WHERE created_at >= ?`, start.UnixMilli()).Scan(
			&dashboard.Summary.RangeFlights, &dashboard.Summary.ActiveUsers); err != nil {
			return Dashboard{}, err
		}
	}
	if dashboard.Summary.LastFlightAt != nil && dashboard.Summary.LastFlightAt.UnixMilli() == 0 {
		dashboard.Summary.LastFlightAt = nil
	}

	if dashboard.Leaderboard, err = s.leaderboard(ctx, start, 50); err != nil {
		return Dashboard{}, err
	}
	if dashboard.RecentFlights, err = s.recentFlights(ctx, 20); err != nil {
		return Dashboard{}, err
	}
	if dashboard.Trend, err = s.trend(ctx, rangeName, now); err != nil {
		return Dashboard{}, err
	}
	if dashboard.Heatmap, err = s.heatmap(ctx, now); err != nil {
		return Dashboard{}, err
	}
	return dashboard, nil
}

func (s *Store) leaderboard(ctx context.Context, start *time.Time, limit int) ([]LeaderboardEntry, error) {
	var rows *sql.Rows
	var err error
	if start == nil {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, username, display_name, avatar_url, total_flights, last_flight_at
FROM users WHERE total_flights > 0
ORDER BY total_flights DESC, last_flight_at DESC, id ASC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at,
       COUNT(f.id) AS range_count, MAX(f.created_at) AS range_last
FROM flights f JOIN users u ON u.id = f.user_id
WHERE f.created_at >= ?
GROUP BY u.id
ORDER BY range_count DESC, range_last DESC, u.id ASC LIMIT ?`, start.UnixMilli(), limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]LeaderboardEntry, 0, limit)
	for rows.Next() {
		var entry LeaderboardEntry
		var last sql.NullInt64
		if start == nil {
			if err := rows.Scan(&entry.User.ID, &entry.User.Username, &entry.User.DisplayName, &entry.User.AvatarURL, &entry.User.TotalFlights, &last); err != nil {
				return nil, err
			}
			entry.FlightCount = entry.User.TotalFlights
			entry.LastFlightAt = nullTime(last)
		} else {
			var rangeLast sql.NullInt64
			if err := rows.Scan(&entry.User.ID, &entry.User.Username, &entry.User.DisplayName, &entry.User.AvatarURL, &entry.User.TotalFlights, &last, &entry.FlightCount, &rangeLast); err != nil {
				return nil, err
			}
			entry.User.LastFlightAt = nullTime(last)
			entry.LastFlightAt = nullTime(rangeLast)
		}
		entry.User.LastFlightAt = nullTime(last)
		entry.Rank = len(entries) + 1
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) recentFlights(ctx context.Context, limit int) ([]Flight, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT f.id, f.created_at, u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at
FROM flights f JOIN users u ON u.id = f.user_id
ORDER BY f.created_at DESC, f.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	flights := make([]Flight, 0, limit)
	for rows.Next() {
		var flight Flight
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&flight.ID, &created, &flight.User.ID, &flight.User.Username, &flight.User.DisplayName, &flight.User.AvatarURL, &flight.User.TotalFlights, &last); err != nil {
			return nil, err
		}
		flight.CreatedAt = time.UnixMilli(created).UTC()
		flight.User.LastFlightAt = nullTime(last)
		flights = append(flights, flight)
	}
	return flights, rows.Err()
}

func (s *Store) trend(ctx context.Context, rangeName string, now time.Time) ([]TrendPoint, error) {
	var bucket time.Duration
	var count int
	switch rangeName {
	case "24h":
		bucket, count = time.Hour, 24
	case "7d":
		bucket, count = 6*time.Hour, 28
	case "1month":
		bucket, count = 24*time.Hour, 30
	case "all":
		var firstMS sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT MIN(created_at) FROM flights`).Scan(&firstMS); err != nil {
			return nil, err
		}
		if !firstMS.Valid {
			return []TrendPoint{}, nil
		}
		duration := now.Sub(time.UnixMilli(firstMS.Int64))
		bucket = 24 * time.Hour
		if duration > 60*24*time.Hour {
			bucket = 7 * 24 * time.Hour
		}
		if duration > 2*365*24*time.Hour {
			bucket = 30 * 24 * time.Hour
		}
		count = int(math.Ceil(float64(duration)/float64(bucket))) + 1
		if count > 120 {
			bucket = time.Duration(math.Ceil(float64(duration)/120/float64(time.Hour))) * time.Hour
			count = 121
		}
	default:
		return nil, fmt.Errorf("unsupported range %q", rangeName)
	}
	start := now.Truncate(bucket).Add(-time.Duration(count-1) * bucket)
	points := make([]TrendPoint, count)
	for i := range points {
		points[i].BucketStart = start.Add(time.Duration(i) * bucket)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ((created_at - ?) / ?) AS bucket_index, COUNT(*)
FROM flights WHERE created_at >= ?
GROUP BY bucket_index ORDER BY bucket_index`, start.UnixMilli(), bucket.Milliseconds(), start.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var index int
		var value int64
		if err := rows.Scan(&index, &value); err != nil {
			return nil, err
		}
		if index >= 0 && index < len(points) {
			points[index].Count = value
		}
	}
	return points, rows.Err()
}

func (s *Store) heatmap(ctx context.Context, now time.Time) ([]HeatCell, error) {
	_, offset := now.In(s.location).Zone()
	modifier := fmt.Sprintf("%+d minutes", offset/60)
	rows, err := s.db.QueryContext(ctx, `
SELECT CAST(strftime('%w', created_at / 1000, 'unixepoch', ?) AS INTEGER) AS weekday,
       CAST(strftime('%H', created_at / 1000, 'unixepoch', ?) AS INTEGER) AS hour,
       COUNT(*)
FROM flights WHERE created_at >= ?
GROUP BY weekday, hour`, modifier, modifier, now.Add(-30*24*time.Hour).UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cells := make([]HeatCell, 0, 168)
	for rows.Next() {
		var cell HeatCell
		if err := rows.Scan(&cell.Weekday, &cell.Hour, &cell.Count); err != nil {
			return nil, err
		}
		cells = append(cells, cell)
	}
	return cells, rows.Err()
}

type pageCursor struct {
	Value int64  `json:"v"`
	ID    string `json:"i"`
}

func (s *Store) Users(ctx context.Context, cursorRaw, sortName string, limit int, now time.Time, rateLimit time.Duration) (UsersPage, error) {
	if limit < 1 {
		limit = 30
	}
	if limit > 100 {
		limit = 100
	}
	column := "COALESCE(last_flight_at, 0)"
	if sortName == "total" {
		column = "total_flights"
	} else if sortName != "" && sortName != "last_flight" {
		return UsersPage{}, errors.New("unsupported user sort")
	}
	query := `SELECT id, username, display_name, avatar_url, total_flights, last_flight_at FROM users`
	args := []any{}
	if cursorRaw != "" {
		cursor, err := decodeCursor(cursorRaw)
		if err != nil {
			return UsersPage{}, errors.New("invalid cursor")
		}
		query += fmt.Sprintf(` WHERE (%s < ? OR (%s = ? AND id > ?))`, column, column)
		args = append(args, cursor.Value, cursor.Value, cursor.ID)
	}
	query += fmt.Sprintf(` ORDER BY %s DESC, id ASC LIMIT ?`, column)
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return UsersPage{}, err
	}
	defer rows.Close()
	users := make([]UserStatus, 0, limit+1)
	for rows.Next() {
		var user User
		var last sql.NullInt64
		if err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.AvatarURL, &user.TotalFlights, &last); err != nil {
			return UsersPage{}, err
		}
		user.LastFlightAt = nullTime(last)
		users = append(users, s.UserStatus(ctx, user, now, rateLimit))
	}
	if err := rows.Err(); err != nil {
		return UsersPage{}, err
	}
	page := UsersPage{}
	if len(users) > limit {
		last := users[limit-1]
		value := int64(0)
		if sortName == "total" {
			value = last.TotalFlights
		} else if last.LastFlightAt != nil {
			value = last.LastFlightAt.UnixMilli()
		}
		page.NextCursor = encodeCursor(pageCursor{Value: value, ID: last.ID})
		users = users[:limit]
	}
	page.Users = users
	return page, nil
}

func rangeStart(name string, now time.Time) (*time.Time, error) {
	var duration time.Duration
	switch name {
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	case "1month":
		duration = 30 * 24 * time.Hour
	case "all":
		return nil, nil
	default:
		return nil, errors.New("range must be 24h, 7d, 1month or all")
	}
	start := now.Add(-duration)
	return &start, nil
}

type rowScanner interface{ Scan(...any) error }

func scanUser(row rowScanner) (User, error) {
	var user User
	var last sql.NullInt64
	if err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.AvatarURL, &user.TotalFlights, &last); err != nil {
		return User{}, err
	}
	user.LastFlightAt = nullTime(last)
	return user, nil
}

func nullTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	t := time.UnixMilli(value.Int64).UTC()
	return &t
}

type nullTimeScanner struct{ target **time.Time }

func newNullTimeScanner(target **time.Time) *nullTimeScanner { return &nullTimeScanner{target: target} }

func (s *nullTimeScanner) Scan(src any) error {
	var value int64
	switch typed := src.(type) {
	case int64:
		value = typed
	case nil:
		*s.target = nil
		return nil
	default:
		return fmt.Errorf("unexpected time value %T", src)
	}
	t := time.UnixMilli(value).UTC()
	*s.target = &t
	return nil
}

func encodeCursor(cursor pageCursor) string {
	data, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeCursor(raw string) (pageCursor, error) {
	var cursor pageCursor
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return cursor, err
	}
	err = json.Unmarshal(data, &cursor)
	return cursor, err
}
