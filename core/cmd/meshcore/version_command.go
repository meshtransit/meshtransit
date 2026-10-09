package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/meshtransit/meshtransit/core/internal/platform/buildinfo"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

type versionOutput struct {
	Version             string `json:"version"`
	Revision            string `json:"revision"`
	GoVersion           string `json:"go_version"`
	ConfigSchemaVersion int    `json:"config_schema_version"`
}

func runVersion(output, errorOutput io.Writer) int {
	build := buildinfo.Current()
	result := versionOutput{
		Version:             build.Version,
		Revision:            build.Revision,
		GoVersion:           build.GoVersion,
		ConfigSchemaVersion: config.SchemaVersion,
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintln(errorOutput, "meshcore: write version output failed")
		return 1
	}
	return 0
}
