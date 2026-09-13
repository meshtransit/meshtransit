package app

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(main *testing.M) {
	goleak.VerifyTestMain(main)
}
