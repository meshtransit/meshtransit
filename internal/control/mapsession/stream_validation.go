package mapsession

import (
	"reflect"
	"time"
)

const (
	minimumStreamOperationTimeout = time.Millisecond
	maximumStreamOperationTimeout = time.Minute
	minimumStreamInterval         = time.Second
	maximumStreamInterval         = 5 * time.Minute
)

func validStreamOptions(options StreamOptions) bool {
	return options.ReplicaID.IsValid() &&
		options.SnapshotTimeout >= minimumStreamOperationTimeout &&
		options.SnapshotTimeout <= maximumStreamOperationTimeout &&
		options.PresenceTTL >= minimumStreamInterval &&
		options.PresenceTTL <= maximumStreamInterval &&
		options.CoordinationTimeout >= minimumStreamOperationTimeout &&
		options.CoordinationTimeout < options.PresenceTTL/3 &&
		options.KeepAliveInterval >= minimumStreamInterval &&
		options.KeepAliveInterval <= maximumStreamInterval &&
		options.ReconcileInterval >= minimumStreamInterval &&
		options.ReconcileInterval <= maximumStreamInterval
}

func isNilStreamDependency(dependency any) bool {
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
