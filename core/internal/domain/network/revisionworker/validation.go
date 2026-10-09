package revisionworker

import (
	"reflect"
	"time"
)

func validOptions(options Options) bool {
	if !validWorkerID(options.WorkerID) || options.BatchSize <= 0 ||
		options.BatchSize > maxBatchSize || options.Lease < minLease ||
		options.Lease > maxLease || options.PollInterval < minPollInterval ||
		options.PollInterval > maxPollInterval || options.RetryDelay < minRetryDelay ||
		options.RetryDelay > maxRetryDelay || options.OperationTimeout < minOperationTimeout ||
		options.OperationTimeout > maxOperationTimeout {
		return false
	}
	claimBudget := time.Duration(options.BatchSize*operationsPerClaim) * options.OperationTimeout
	return options.Lease > claimBudget
}

func validWorkerID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func isNilDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
