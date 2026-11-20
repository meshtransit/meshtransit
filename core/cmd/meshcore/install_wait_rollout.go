package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/adapter/kubeapi"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

const (
	envRolloutInstance = "MESHTRANSIT_ROLLOUT_INSTANCE"
	envRolloutChart    = "MESHTRANSIT_ROLLOUT_CHART"
	envRolloutImages   = "MESHTRANSIT_ROLLOUT_IMAGES"
	envRolloutTimeout  = "MESHTRANSIT_ROLLOUT_TIMEOUT"
	rolloutPoll        = 5 * time.Second
	defaultRolloutWait = 10 * time.Minute
	maximumRolloutWait = 30 * time.Minute
	maximumComponents  = 8
	coreRoleVariable   = "MESHTRANSIT_ROLE"
)

var (
	rolloutName       = regexp.MustCompile(`^[a-z0-9]([-.a-z0-9]{0,61}[a-z0-9])?$`)
	errRolloutSetting = errors.New("wait-rollout: invalid setting")
	errRolloutTimeout = errors.New("wait-rollout: pods of an earlier release are still there")
	// coreRoles serve Core's schema; their containers set MESHTRANSIT_ROLE.
	coreRoles = []string{"api", "control", "worker", "all"}
)

// rolloutLister lists the release's pods and ReplicaSets.
type rolloutLister interface {
	ListPods(ctx context.Context, labelSelector string) ([]kubeapi.Pod, error)
	ListReplicaSets(ctx context.Context, labelSelector string) ([]kubeapi.ReplicaSet, error)
}

// runInstallWaitRollout is "meshcore install wait-rollout": it waits until
// no earlier code of the release can serve, so the operator's after-rollout
// steps (which take grants that code needs) may run. Every pod of the
// release whose container serves Core (MESHTRANSIT_ROLE api, control,
// worker or all) must run this release's image for its component and not
// be shutting down, and every ReplicaSet with another image must be at
// zero, desired and actual. A component removed or renamed in this release
// blocks until its pods are gone. Settings: MESHTRANSIT_ROLLOUT_INSTANCE,
// MESHTRANSIT_ROLLOUT_CHART (the chart's name label), MESHTRANSIT_ROLLOUT_IMAGES
// (component=image,…), MESHTRANSIT_ROLLOUT_TIMEOUT.
func runInstallWaitRollout(ctx context.Context, lookup config.LookupFunc, output, errorOutput io.Writer,
	lister func() (rolloutLister, error), poll time.Duration,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	settings, err := loadRolloutSettings(lookup, poll)
	if err != nil {
		logger.ErrorContext(ctx, "wait-rollout failed", "error_code", "invalid_rollout_configuration", "error", err)
		return 1
	}
	kube, err := lister()
	if err != nil {
		logger.ErrorContext(ctx, "wait-rollout failed", "error_code", "install_kubernetes_unavailable", "error", err)
		return 1
	}
	waitContext, cancel := context.WithTimeout(ctx, settings.timeout)
	defer cancel()
	for {
		blocking, pods, err := settings.blocking(waitContext, kube)
		switch {
		case errors.Is(err, kubeapi.ErrDenied) || errors.Is(err, kubeapi.ErrConfig):
			logger.ErrorContext(ctx, "wait-rollout failed", "error_code", "install_kubernetes_denied", "error", err)
			return 1
		case err != nil && waitContext.Err() == nil:
			// A passing API error (an API server upgrade, a 429): try again.
			logger.WarnContext(ctx, "wait-rollout could not read the release", "error", err)
		case err == nil && len(blocking) == 0:
			return writeInstallReport(output, map[string]any{"operation": "install wait-rollout", "pods": pods})
		case err == nil:
			logger.InfoContext(ctx, "waiting for the rollout", "blocking", blocking)
		}
		select {
		case <-waitContext.Done():
			logger.ErrorContext(ctx, "wait-rollout failed", "error_code", "rollout_timeout", "error", errRolloutTimeout,
				"blocking", blocking)
			return 1
		case <-time.After(poll):
		}
	}
}

type rolloutSettings struct {
	instance, chart string
	images          map[string]string // component -> image
	timeout         time.Duration
}

func loadRolloutSettings(lookup config.LookupFunc, poll time.Duration) (rolloutSettings, error) {
	instance, _ := lookup(envRolloutInstance)
	if !rolloutName.MatchString(instance) {
		return rolloutSettings{}, fmt.Errorf("%w: %s", errRolloutSetting, envRolloutInstance)
	}
	chart, _ := lookup(envRolloutChart)
	if !rolloutName.MatchString(chart) {
		return rolloutSettings{}, fmt.Errorf("%w: %s", errRolloutSetting, envRolloutChart)
	}
	images, err := parseRolloutImages(lookup)
	if err != nil {
		return rolloutSettings{}, err
	}
	timeout := defaultRolloutWait
	if text, ok := lookup(envRolloutTimeout); ok {
		parsed, err := time.ParseDuration(text)
		if err != nil || parsed < poll || parsed > maximumRolloutWait {
			return rolloutSettings{}, fmt.Errorf("%w: %s", errRolloutSetting, envRolloutTimeout)
		}
		timeout = parsed
	}
	return rolloutSettings{instance: instance, chart: chart, images: images, timeout: timeout}, nil
}

func parseRolloutImages(lookup config.LookupFunc) (map[string]string, error) {
	text, _ := lookup(envRolloutImages)
	invalid := fmt.Errorf("%w: %s", errRolloutSetting, envRolloutImages)
	if text == "" {
		return nil, invalid
	}
	images := map[string]string{}
	for _, pair := range strings.Split(text, ",") {
		component, image, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || !rolloutName.MatchString(component) || image == "" || len(image) > 512 ||
			strings.ContainsAny(image, " ,()") {
			return nil, invalid
		}
		if _, duplicate := images[component]; duplicate {
			return nil, invalid
		}
		images[component] = image
	}
	if len(images) > maximumComponents {
		return nil, invalid
	}
	return images, nil
}

func (settings rolloutSettings) selector() string {
	return "app.kubernetes.io/instance=" + settings.instance + ",app.kubernetes.io/name=" + settings.chart
}

// blocking names what still holds the rollout and counts the release's
// Core pods.
func (settings rolloutSettings) blocking(ctx context.Context, kube rolloutLister) ([]string, int, error) {
	pods, err := kube.ListPods(ctx, settings.selector())
	if err != nil {
		return nil, 0, fmt.Errorf("list pods: %w", err)
	}
	replicaSets, err := kube.ListReplicaSets(ctx, settings.selector())
	if err != nil {
		return nil, 0, fmt.Errorf("list ReplicaSets: %w", err)
	}
	blocking, serving := rolloutBlockingPods(pods, settings.images)
	blocking = append(blocking, rolloutBlockingReplicaSets(replicaSets, settings.images)...)
	slices.Sort(blocking)
	return blocking, serving, nil
}

// coreContainer is the container of a pod template that serves Core: it
// sets MESHTRANSIT_ROLE to a Core role. Sidecars and other images do not.
func coreContainer(containers []kubeapi.Container) (kubeapi.Container, bool) {
	for _, container := range containers {
		if slices.Contains(coreRoles, container.EnvValue(coreRoleVariable)) {
			return container, true
		}
	}
	return kubeapi.Container{}, false
}

// rolloutBlockingPods names the pods that still hold the rollout: a Core
// pod shutting down, running another image than its component's, or of a
// component this release does not run. Finished pods do not count.
func rolloutBlockingPods(pods []kubeapi.Pod, images map[string]string) ([]string, int) {
	blocking := []string{}
	serving := 0
	for _, pod := range pods {
		container, core := coreContainer(pod.Spec.Containers)
		if !core || pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			continue
		}
		serving++
		expected := images[pod.Metadata.Labels["app.kubernetes.io/component"]]
		if pod.Metadata.DeletionTimestamp != nil || !sameImage(container.Image, expected) {
			blocking = append(blocking, "pod/"+pod.Metadata.Name)
		}
	}
	return blocking, serving
}

// rolloutBlockingReplicaSets names the ReplicaSets of earlier code that may
// still start a pod: another image, desired or actual replicas above zero.
func rolloutBlockingReplicaSets(replicaSets []kubeapi.ReplicaSet, images map[string]string) []string {
	blocking := []string{}
	for _, replicaSet := range replicaSets {
		container, core := coreContainer(replicaSet.Spec.Template.Spec.Containers)
		if !core {
			continue
		}
		expected := images[replicaSet.Spec.Template.Metadata.Labels["app.kubernetes.io/component"]]
		if sameImage(container.Image, expected) {
			continue
		}
		desired := replicaSet.Spec.Replicas == nil || *replicaSet.Spec.Replicas > 0
		if desired || replicaSet.Status.Replicas > 0 {
			blocking = append(blocking, "replicaset/"+replicaSet.Metadata.Name)
		}
	}
	return blocking
}

// sameImage compares an image a pod runs with the expected one: by digest
// when the expected names one (an admission webhook may rewrite the
// registry or repository spelling), else exactly.
func sameImage(running, expected string) bool {
	if expected == "" {
		return false
	}
	if _, digest, pinned := strings.Cut(expected, "@sha256:"); pinned {
		_, runningDigest, runningPinned := strings.Cut(running, "@sha256:")
		return runningPinned && runningDigest == digest
	}
	return running == expected
}
