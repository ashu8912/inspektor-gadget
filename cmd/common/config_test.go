// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

const testConfig = `
---
flag: cvalue
flag-with-default: cvalue
`

func TestConfig(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		config          string
		wantFlag        string
		wantFlagDefault string
	}{
		{
			name:            "flags precedence over defaults",
			args:            []string{"--flag", "fvalue", "--flag-with-default", "fvalue"},
			wantFlag:        "fvalue",
			wantFlagDefault: "fvalue",
		},
		{
			name:            "flag precedence over config",
			args:            []string{"--flag", "fvalue", "--flag-with-default", "fvalue"},
			config:          testConfig,
			wantFlag:        "fvalue",
			wantFlagDefault: "fvalue",
		},
		{
			name:            "config precedence over defaults",
			config:          testConfig,
			wantFlag:        "cvalue",
			wantFlagDefault: "cvalue",
		},
		{
			name:            "default values only",
			args:            []string{},
			wantFlagDefault: "dvalue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test command with some flags.
			c := &cobra.Command{
				Use:  "testcmd",
				RunE: func(cmd *cobra.Command, args []string) error { return nil },
			}
			c.PersistentFlags().String("flag", "", "")
			c.PersistentFlags().String("flag-with-default", "dvalue", "")

			// Add config handling to the command.
			AddConfigHandling(c)
			require.NotNil(t, c.PersistentPreRunE)

			// Write the config file to the temp directory and set the config paths.
			dir := t.TempDir()
			cf := filepath.Join(dir, configKey+"."+configType)
			err := os.WriteFile(cf, []byte(tt.config), 0o644)
			require.NoError(t, err)
			configPaths = []string{dir}

			c.SetArgs(tt.args)
			err = c.Execute()
			require.NoError(t, err)

			c.Flags().VisitAll(func(f *pflag.Flag) {
				flagName := f.Name
				flagValue := f.Value.String()
				switch flagName {
				case "flag":
					require.Equal(t, tt.wantFlag, flagValue)
				case "flag-with-default":
					require.Equal(t, tt.wantFlagDefault, flagValue)
				}
			})
		})
	}
}
