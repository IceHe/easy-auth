package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	database, err := openDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	whitelistIPs, whitelistNets, err := parseIPWhitelist(cfg.RateLimitIPWhitelist)
	if err != nil {
		log.Fatalf("parse rate limit whitelist: %v", err)
	}

	server := &Server{
		cfg:        cfg,
		db:         database,
		tokenCache: NewTokenCache(cfg.TokenCacheEnabled, cfg.TokenCacheTTL, cfg.TokenCacheMaxSize),
		rateLimiter: &RateLimiter{
			enabled:       cfg.RateLimitEnabled,
			trustProxy:    cfg.RateLimitTrustProxy,
			whitelistIPs:  whitelistIPs,
			whitelistNets: whitelistNets,
			hits:          make(map[string][]time.Time),
		},
		assets: mustAssets(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.bootstrap(ctx); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           server.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
