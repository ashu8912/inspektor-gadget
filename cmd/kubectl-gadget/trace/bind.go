// Copyright 2019-2022 The Inspektor Gadget authors
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

package trace

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	commontrace "github.com/kinvolk/inspektor-gadget/cmd/common/trace"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/bind/types"
)

func newBindCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	var (
		// flags
		targetPid    uint
		targetPorts  []uint
		ignoreErrors bool
	)

	cmd := &cobra.Command{
		Use:   "bind",
		Short: "Trace the kernel functions performing socket binding",
		RunE: func(cmd *cobra.Command, args []string) error {
			portsStringSlice := []string{}
			for _, port := range targetPorts {
				portsStringSlice = append(portsStringSlice, strconv.FormatUint(uint64(port), 10))
			}

			bindGadget := &TraceGadget[types.Event]{
				name:        "bindsnoop",
				commonFlags: &commonFlags,
				parser:      commontrace.NewBindParserWithK8sInfo(&commonFlags.OutputConfig),
				params: map[string]string{
					"pid":           strconv.FormatUint(uint64(targetPid), 10),
					"ports":         strings.Join(portsStringSlice, ","),
					"ignore_errors": strconv.FormatBool(ignoreErrors),
				},
			}

			return bindGadget.Run()
		},
	}

	cmd.PersistentFlags().UintVarP(
		&targetPid,
		"pid",
		"",
		0,
		"Show only bind events generated by this particular PID",
	)
	cmd.PersistentFlags().UintSliceVarP(
		&targetPorts,
		"ports",
		"P",
		[]uint{},
		"Trace only bind events involving these ports",
	)
	cmd.PersistentFlags().BoolVarP(
		&ignoreErrors,
		"ignore-errors",
		"i",
		true,
		"Show only events where the bind succeeded",
	)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
