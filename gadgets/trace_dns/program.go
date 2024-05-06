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

package main

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm/api"
)

//export init
func gadgetInit() int {
	ds, err := api.GetDataSource("dns")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	nameF, err := ds.GetField("name")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		payload := nameF.Bytes(data)

		var str string
		for i := 0; i < len(payload); i++ {
			length := int(payload[i])
			if length == 0 {
				break
			}
			if i+1+length < len(payload) {
				str += string(payload[i+1:i+1+length]) + "."
			} else {
				api.Warnf("invalid payload %+v", payload)
				return
			}
			i += length
		}
		nameF.SetString(data, str)
	}, 0)

	return 0
}

func main() {}
