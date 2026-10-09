package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	transitionTimeout = 30 * time.Second
	connectTimeout    = 5 * time.Second
	shutdownTimeout   = 2 * time.Second
)

type publicIDGenerator func() (publicid.ID, error)

func executeTransition(
	ctx context.Context,
	spec transitionSpec,
	database databaseSettings,
) (output transitionOutput, resultErr error) {
	operationCtx, cancel := context.WithTimeout(ctx, transitionTimeout)
	defer cancel()

	command, err := buildPublicationCommand(spec, publicid.New)
	if err != nil {
		return transitionOutput{}, fmt.Errorf("build policy publication command: %w", err)
	}
	pool, err := postgresadapter.Open(operationCtx, postgresadapter.Options{
		Role:           postgresadapter.PoolRoleRuntime,
		Address:        database.address,
		Database:       database.database,
		User:           database.user,
		PasswordFile:   database.passwordFile,
		CAFile:         database.trustFile,
		MaxConnections: 1,
		ConnectTimeout: connectTimeout,
	})
	if err != nil {
		return transitionOutput{}, fmt.Errorf("open qualification postgres pool: %w", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.WithoutCancel(operationCtx),
			shutdownTimeout,
		)
		defer cleanupCancel()
		resultErr = errors.Join(resultErr, pool.Shutdown(cleanupCtx))
	}()
	if err := pool.Check(operationCtx); err != nil {
		return transitionOutput{}, fmt.Errorf("check qualification postgres pool: %w", err)
	}

	store, err := postgresadapter.NewPolicyPublicationStore(
		pool,
		postgresadapter.PolicyPublicationOptions{
			StatementTimeout:  5 * time.Second,
			LockTimeout:       2 * time.Second,
			IdleTimeout:       10 * time.Second,
			AllowTrustedActor: true,
			ApprovalMode:      postgresadapter.PolicyPublicationApprovalModeQualificationBypass,
		},
	)
	if err != nil {
		return transitionOutput{}, fmt.Errorf("construct policy publication store: %w", err)
	}
	retry, err := policypublication.NewExponentialBackoff(10*time.Millisecond, 100*time.Millisecond)
	if err != nil {
		return transitionOutput{}, fmt.Errorf("construct policy publication retry: %w", err)
	}
	service, err := policypublication.NewService(
		policypublication.Options{MaxAttempts: 3, RollbackTimeout: shutdownTimeout},
		policypublication.Dependencies{
			Transactions:     store,
			CommittedResults: store,
			MutationIDs:      policypublication.PublicMutationIDGenerator{},
			Clock:            policypublication.SystemClock{},
			Retry:            retry,
		},
	)
	if err != nil {
		return transitionOutput{}, fmt.Errorf("construct policy publication service: %w", err)
	}
	result, err := service.Publish(operationCtx, command)
	if err != nil {
		return transitionOutput{}, fmt.Errorf("publish qualification policy: %w", err)
	}
	return transitionOutput{
		Mode:            string(spec.mode),
		RuleCount:       len(command.Candidate().Snapshot().Rules()),
		PolicyRevision:  result.PolicyRevision(),
		NetworkRevision: result.NetworkRevision(),
		ReleaseID:       result.ReleaseID().String(),
	}, nil
}

func buildPublicationCommand(
	spec transitionSpec,
	newID publicIDGenerator,
) (policypublication.Command, error) {
	if !spec.isValid() || newID == nil {
		return policypublication.Command{}, errInvalidInput
	}
	rules := []policy.Rule{}
	if spec.mode == transitionModeBidirectionalICMP {
		directions := [][2]node.ID{
			{spec.sourceNodeID, spec.destinationNodeID},
			{spec.destinationNodeID, spec.sourceNodeID},
		}
		for _, direction := range directions {
			id, err := newID()
			if err != nil {
				return policypublication.Command{}, fmt.Errorf("generate access rule id: %w", err)
			}
			ruleID, err := policy.ParseRuleID(id.String())
			if err != nil {
				return policypublication.Command{}, fmt.Errorf("parse generated access rule id: %w", err)
			}
			rule, err := policy.NewRule(policy.RuleParams{
				ID:                ruleID,
				Scope:             spec.scope,
				SourceNodeID:      direction[0],
				DestinationNodeID: direction[1],
				Protocol:          policy.ProtocolICMP,
			})
			if err != nil {
				return policypublication.Command{}, fmt.Errorf("construct icmp access rule: %w", err)
			}
			rules = append(rules, rule)
		}
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    spec.scope,
		Revision: spec.basePolicyRevision + 1,
		Rules:    rules,
	})
	if err != nil {
		return policypublication.Command{}, fmt.Errorf("construct policy snapshot: %w", err)
	}
	candidate, err := policypublication.NewCandidate(snapshot, 1)
	if err != nil {
		return policypublication.Command{}, fmt.Errorf("construct policy candidate: %w", err)
	}
	command, err := policypublication.NewCommand(policypublication.CommandParams{
		Candidate:          candidate,
		BasePolicyRevision: spec.basePolicyRevision,
		ActorPrincipalID:   spec.actorPrincipalID,
		AuditReason:        spec.auditReason,
	})
	if err != nil {
		return policypublication.Command{}, fmt.Errorf("construct policy publication command: %w", err)
	}
	return command, nil
}
