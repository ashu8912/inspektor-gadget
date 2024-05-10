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
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	configKey  = "config"
	configType = "yaml"
)

var configPaths = []string{"/etc/ig/", "$HOME/.ig/", "."}

// AddConfigHandling adds the config handling to the command. It uses following order of precedence:
// 1. Flags
// 2. Config file [/etc/ig/config.yaml, $HOME/.ig/config.yaml, ./config.yaml]
// 3. Defaults
func AddConfigHandling(cmd *cobra.Command) {
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		v := viper.New()
		v.SetConfigName(configKey)
		v.SetConfigType(configType)
		for _, path := range configPaths {
			v.AddConfigPath(path)
		}

		// we don't care about the error here, as the config file is optional
		v.ReadInConfig()

		if err := bindFlags(cmd, v); err != nil {
			return fmt.Errorf("binding flags: %w", err)
		}

		// we also manually need to check the verbose flag, as PersistentPreRunE in
		// verbose.go will not have the correct information due to manually parsing
		// the flags
		checkVerboseFlag()
		if v.ConfigFileUsed() != "" {
			log.Debugf("Using config file: %s", v.ConfigFileUsed())
		} else {
			log.Debug("No config file found")
		}

		// inform user about the unused config keys
		for _, key := range v.AllKeys() {
			if cmd.Flags().Lookup(key) == nil {
				log.Debugf("Ignoring unused config key: %s", key)
			}
		}

		return nil
	}
}

func bindFlags(command *cobra.Command, v *viper.Viper) error {
	command.Flags().VisitAll(func(f *pflag.Flag) {
		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			if err := command.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				fmt.Printf("Error binding config value: %v\n", err)
			}
		}
	})
	return nil
}
