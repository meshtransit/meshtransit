package main

import (
	"context"
	"fmt"
	"io"

	"meshtransit.net/core/internal/adapter/kubeapi"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/platform/config"
)

const usage = "Usage: meshcore [serve | version | config validate | identity fingerprint [publish] | identity migrate | migrate status | migrate up | migrate verify | migrate operator status | migrate operator apply [--dry-run] [--after-rollout] [--through N] | redis acl apply | redis acl rules api|control|worker|all | bootstrap check | bootstrap apply | install bootstrap postgres|kubernetes|deployment | install wait-rollout | setup init|secrets|approve-identity|render|check|apply|migrate|renew-tls [--config F] [--state-dir D] | account revoke-sessions|quarantine|release <principal-id> | workspace feature grant <workspace-id> connection_logs <note> | workspace feature revoke <workspace-id> connection_logs | workspace feature list <workspace-id> | kubernetes-ca status|rewrap|rotate-data-key|retire-ca --workspace W --network N [--ca C --reason R] [--actor A --change-ref R] | kubernetes-ca guard | kubernetes-ca mark-restored --actor A --change-ref R | kubernetes-ca reconcile-after-restore --actor A --change-ref R --roots-checked-since T]\n"

func execute(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
) int {
	switch {
	case len(args) == 0:
		return run(ctx, lookup, errorOutput)
	case len(args) == 1 && args[0] == "serve":
		return run(ctx, lookup, errorOutput)
	case len(args) == 1 && args[0] == "version":
		return runVersion(output, errorOutput)
	case len(args) == 2 && args[0] == "config" && args[1] == "validate":
		return runConfigValidate(ctx, lookup, output, errorOutput)
	case len(args) == 2 && args[0] == "identity" && args[1] == "fingerprint":
		return runIdentityFingerprint(ctx, lookup, output, errorOutput)
	case len(args) == 3 && args[0] == "identity" && args[1] == "fingerprint" && args[2] == "publish":
		return runIdentityFingerprintPublish(ctx, lookup, output, errorOutput, calculateIdentityFingerprint,
			func() (identityFingerprintStore, error) {
				kubeConfig, err := kubeapi.InCluster()
				if err != nil {
					return nil, err
				}
				return kubeapi.New(kubeConfig)
			})
	case len(args) == 2 && args[0] == "identity" && args[1] == "migrate":
		return runIdentityMigrate(ctx, lookup, output, errorOutput)
	case len(args) == 2 && args[0] == "migrate" && (args[1] == "status" || args[1] == "up" || args[1] == "verify"):
		return runMigrate(ctx, args[1], lookup, output, errorOutput, openMigrationService)
	case len(args) >= 2 && args[0] == "migrate" && args[1] == "operator":
		return runMigrateOperator(ctx, args[2:], lookup, output, errorOutput, openOperatorService)
	case len(args) >= 2 && args[0] == "redis" && args[1] == "acl":
		return runRedisACL(ctx, args[2:], lookup, output, errorOutput, redisadapter.ApplyACL)
	case len(args) == 2 && args[0] == "bootstrap" && (args[1] == "check" || args[1] == "apply"):
		return runBootstrap(ctx, args[1], lookup, output, errorOutput)
	case len(args) >= 1 && args[0] == "install":
		return runInstall(ctx, args[1:], lookup, output, errorOutput, productionInstallDependencies())
	case len(args) >= 2 && args[0] == "setup":
		return runSetup(ctx, args[1:], output, errorOutput)
	case len(args) >= 2 && args[0] == "kubernetes-ca":
		return runKubernetesCA(ctx, args[1:], lookup, output, errorOutput)
	case len(args) >= 2 && args[0] == "workspace" && args[1] == "feature":
		return runWorkspaceFeature(ctx, args[2:], lookup, output, errorOutput)
	case len(args) == 3 && args[0] == "account" && accountCommandActions[args[1]] != "":
		return runAccount(ctx, args[1], args[2], lookup, output, errorOutput)
	case len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help"):
		if _, err := io.WriteString(output, usage); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "meshcore: write help output failed")
			return 1
		}
		return 0
	default:
		if _, err := io.WriteString(errorOutput, usage); err != nil {
			return 1
		}
		return 2
	}
}
