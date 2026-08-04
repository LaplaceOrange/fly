package main

import (
	"context"
	"embed"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LaplaceOrange/fly/internal/config"
	"github.com/LaplaceOrange/fly/internal/cpoauth"
	"github.com/LaplaceOrange/fly/internal/realtime"
	"github.com/LaplaceOrange/fly/internal/server"
	"github.com/LaplaceOrange/fly/internal/store"
	"github.com/LaplaceOrange/fly/internal/turnstile"
)

//go:embed all:web/dist
var frontend embed.FS

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.DatabasePath, cfg.Location)
	if err != nil {
		logger.Error("database startup failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	hub := realtime.NewHub()
	app := server.New(server.Dependencies{
		Config:     cfg,
		Store:      db,
		CPOAuth:    cpoauth.New(cfg.CPOAuthTokenURL, cfg.CPOAuthUserInfoURL, 10*time.Second),
		Turnstile:  turnstile.New(cfg.TurnstileSecretKey, cfg.TurnstileExpectedHostname, cfg.TurnstileExpectedAction, 8*time.Second),
		Hub:        hub,
		FrontendFS: frontend,
		Logger:     logger,
	})

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       75 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go db.CleanupExpiredSessions(ctx, 12*time.Hour, logger)

	go func() {
		logger.Info("server listening", "address", cfg.ListenAddr, "base_url", cfg.PublicBaseURL.String())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hub.Close()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}
