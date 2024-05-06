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

package wasm

import (
	"context"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
)

func (i *wasmOperatorInstance) addLogFuncs(env wazero.HostModuleBuilder) {
	logFn := func(ctx context.Context, m wapi.Module, stack []uint64) {
		buf, err := stringFromStack(m, stack[1])
		if err != nil {
			i.logger.Warnf("reading string from stack: %v", err)
			return
		}

		switch stack[0] {
		case 0:
			i.logger.Error(buf)
		case 1:
			i.logger.Warn(buf)
		case 2:
			i.logger.Info(buf)
		case 3:
			i.logger.Debug(buf)
		case 4:
			i.logger.Trace(buf)
		}
	}

	exportFunction(env, "gadgetLog", logFn,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // log level
			wapi.ValueTypeI64, // message
		},
		[]wapi.ValueType{},
	)
}
