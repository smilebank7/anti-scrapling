package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/server"
)

var Version = "dev"

func main() {
	var (
		configPath  = flag.String("config", "/etc/anti-scrapling/policy.yaml", "policy YAML path")
		showVer     = flag.Bool("version", false, "print version and exit")
		metricsBind = flag.String("metrics-bind", ":9090", "metrics server bind address")
		adminBind   = flag.String("admin-bind", ":9091", "admin/audit server bind address")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(Version)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err, "path", *configPath)
		os.Exit(1)
	}

	d, err := buildDeps(cfg)
	if err != nil {
		slog.Error("failed to build dependencies", "error", err)
		os.Exit(1)
	}

	mainSrv := server.New(cfg.Bind, buildMainHandler(d), buildServerTLSConfig(cfg.Policy.Listener.TLS))
	metricsSrv := server.New(*metricsBind, d.metrics.Handler(), nil)
	adminSrv := server.New(*adminBind, buildAdminHandler(d), nil)

	serveErrs := make(chan error, 3)
	go func() { serveErrs <- mainSrv.Start() }()
	go func() { serveErrs <- metricsSrv.Start() }()
	go func() { serveErrs <- adminSrv.Start() }()

	d.health.SetReady(true)
	d.logger.Info("anti-scrapling started",
		"version", Version,
		"bind", cfg.Bind,
		"target", cfg.Target,
		"metrics", *metricsBind,
		"admin", *adminBind,
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		d.logger.Info("received signal, shutting down", "signal", sig)
	case err := <-serveErrs:
		if err != nil {
			d.logger.Error("server error, shutting down", "error", err)
		}
	}

	d.health.SetReady(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_ = mainSrv.Stop(shutdownCtx)
	_ = metricsSrv.Stop(shutdownCtx)
	_ = adminSrv.Stop(shutdownCtx)
	_ = d.cache.Close()

	d.logger.Info("shutdown complete")
}
