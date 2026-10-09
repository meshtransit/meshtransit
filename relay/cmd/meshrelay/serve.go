package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"meshtransit.net/relay/internal/metrics"
	"meshtransit.net/relay/internal/server"
	"meshtransit.net/relay/internal/stunserver"
	"meshtransit.net/relay/internal/udp"
	"meshtransit.net/shared/mtrp"
)

// serve runs the relay until ctx is done, then drains clients and stops.
func serve(ctx context.Context, cfg serveConfig, logOut io.Writer) error {
	level, err := parseLevel(cfg.logLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: slog.Level(level)}))
	relayKey, err := loadRelayKey(cfg.keyFile)
	if err != nil {
		return err
	}
	m := metrics.New()

	udpListener, err := udp.Listen(cfg.udpAddr, mtrp.MaxUDPFrame)
	if err != nil {
		return err
	}
	defer func() { _ = udpListener.Close() }()
	relay, err := server.New(server.Config{
		Key:     relayKey,
		Keys:    mtrp.NewStaticKeys(cfg.signingKeys...),
		UDP:     udpListener,
		Logger:  logger,
		Metrics: m,
	})
	if err != nil {
		return err
	}

	var stun *stunserver.Server
	if cfg.stunAddr != "" {
		stun, err = stunserver.Listen(stunserver.Config{
			Primary:    cfg.stunAddr,
			AltPort:    cfg.stunAltPort,
			PublicAddr: cfg.publicIP,
			Metrics:    m.STUN,
		})
		if err != nil {
			return err
		}
		defer stun.Close()
	}

	admin, err := listenAdmin(ctx, cfg.adminAddr, m.Handler(), relay)
	if err != nil {
		return err
	}

	logger.Info("relay started",
		"version", version, "public_key", relay.PublicKey().String(),
		"udp", udpListener.LocalAddr().String(), "stun", cfg.stunAddr, "stun_alt", cfg.stunAltPort,
		"trusted_signing_keys", len(cfg.signingKeys))

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	wg.Go(func() { errs <- udpListener.Serve(runCtx, cfg.udpReaders, relay.HandleUDP) })
	wg.Go(func() { errs <- ignoreCanceled(relay.Run(runCtx)) })
	if stun != nil {
		wg.Go(func() { errs <- stun.Serve(runCtx) })
	}
	wg.Go(func() { errs <- ignoreServerClosed(admin.server.Serve(admin.listener)) })

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
	}
	// Ask clients to move to another relay, give them time, then stop.
	logger.Info("relay draining", "timeout", cfg.drainTimeout.String())
	relay.Drain(cfg.drainTimeout)
	select {
	case <-time.After(cfg.drainTimeout):
	case runErr = <-errs:
	}
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	_ = admin.server.Shutdown(shutdownCtx)
	wg.Wait()
	close(errs)
	for err := range errs {
		runErr = errors.Join(runErr, err)
	}
	logger.Info("relay stopped")
	return runErr
}

type adminServer struct {
	server   *http.Server
	listener net.Listener
}

// listenAdmin serves /metrics and /healthz. It binds to localhost by
// default; exposing it is an operator decision.
func listenAdmin(ctx context.Context, addr string, metricsHandler http.Handler, relay *server.Server) (adminServer, error) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "ok %d sessions\n", relay.SessionCount())
	})
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return adminServer{}, fmt.Errorf("admin listen %s: %w", addr, err)
	}
	return adminServer{
		server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		},
		listener: l,
	}, nil
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func ignoreServerClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
