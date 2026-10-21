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

	"meshtransit.net/relay/internal/corelink"
	"meshtransit.net/relay/internal/metrics"
	"meshtransit.net/relay/internal/probe"
	"meshtransit.net/relay/internal/server"
	"meshtransit.net/relay/internal/stream"
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
	var (
		relay *server.Server
		link  *corelink.Link
		keys  mtrp.KeySet = mtrp.NewStaticKeys(cfg.signingKeys...)
		revs  mtrp.Revocations
	)
	if cfg.coreURL != "" {
		link, err = corelink.New(corelink.Config{
			CoreURL: cfg.coreURL, Bootstrap: cfg.signingKeys, Self: relayKey.Public(),
			OnDrain: func() { relay.Drain(cfg.drainTimeout) },
			Logger:  logger, Metrics: m.CoreLink, Revocations: m.Revocations,
			Private: cfg.private, Key: relayKey,
		})
		if err != nil {
			return err
		}
		keys, revs = link, link
	}
	relay, err = server.New(server.Config{
		Key:         relayKey,
		Keys:        keys,
		Revocations: revs,
		UDP:         udpListener,
		// Mbit/s to bytes/s.
		NetworkBytesPerSecond: float64(cfg.networkMbit) * 125_000,
		Logger:                logger,
		Metrics:               m,
	})
	if err != nil {
		return err
	}

	var stun *stunserver.Server
	if cfg.stunAddr != "" {
		stun, err = stunserver.Listen(stunserver.Config{
			Primary:     cfg.stunAddr,
			AltPort:     cfg.stunAltPort,
			PublicAddr:  cfg.publicIP,
			PublicAddr6: cfg.publicIPv6,
			Metrics:     m.STUN,
		})
		if err != nil {
			return err
		}
		defer stun.Close()
	}

	var streams *stream.Listener
	if cfg.tlsAddr != "" {
		tlsConf, err := tlsConfig(cfg, logger, m.CertificateServed)
		if err != nil {
			return err
		}
		streams, err = stream.Listen(ctx, stream.Config{
			Addr: cfg.tlsAddr, TLS: tlsConf, Handler: relay, Logger: logger, Metrics: m.Stream,
			MaxConns: cfg.tlsMaxConns, MaxConnsPerIP: cfg.tlsMaxPerIP,
		})
		if err != nil {
			return err
		}
		defer func() { _ = streams.Close() }()
	}

	admin, err := listenAdmin(ctx, cfg.adminAddr, m.Handler(), relay)
	if err != nil {
		return err
	}
	var probes *probe.Server
	if cfg.probeAddr != "" {
		if probes, err = probe.Listen(ctx, cfg.probeAddr, m.Probe); err != nil {
			return err
		}
	}

	logger.Info("relay started",
		"version", version, "public_key", relay.PublicKey().String(),
		"udp", udpListener.LocalAddr().String(), "stun", cfg.stunAddr, "stun_alt", cfg.stunAltPort, "tls", cfg.tlsAddr,
		"probe", cfg.probeAddr, "trusted_signing_keys", len(cfg.signingKeys))

	if link != nil {
		// Admit no session before Core's revocations are known: the sockets
		// are bound but not read until the first state is applied, or until
		// initialStateWait passes (then the relay serves on its bootstrap
		// keys, and tickets, valid for minutes, bound the exposure).
		if err := pollInitialState(ctx, link); err != nil {
			logger.Warn("initial relay state poll failed; serving with bootstrap keys", "error", err)
		}
	}

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 7)
	wg.Go(func() { errs <- udpListener.Serve(runCtx, cfg.udpReaders, relay.HandleUDP) })
	wg.Go(func() { errs <- ignoreCanceled(relay.Run(runCtx)) })
	if stun != nil {
		wg.Go(func() { errs <- stun.Serve(runCtx) })
	}
	if streams != nil {
		wg.Go(func() { errs <- streams.Serve(runCtx) })
	}
	if link != nil {
		wg.Go(func() { errs <- link.Run(runCtx) })
	}
	wg.Go(func() { errs <- ignoreServerClosed(admin.server.Serve(admin.listener)) })
	if probes != nil {
		wg.Go(func() { errs <- probes.Serve() })
	}

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
	if probes != nil {
		_ = probes.Shutdown(shutdownCtx)
	}
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

// initialStateWait bounds how long a starting relay waits for Core's first
// relay state before serving.
const initialStateWait = 20 * time.Second

// pollInitialState polls Core until one state is applied, retrying after 1,
// 2 and 4 seconds within initialStateWait.
func pollInitialState(ctx context.Context, link *corelink.Link) error {
	ctx, cancel := context.WithTimeout(ctx, initialStateWait)
	defer cancel()
	var err error
	for retry := time.Second; ; retry *= 2 {
		pollCtx, cancelPoll := context.WithTimeout(ctx, corelink.DefaultTimeout)
		err = link.Poll(pollCtx)
		cancelPoll()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(retry):
		}
	}
}
