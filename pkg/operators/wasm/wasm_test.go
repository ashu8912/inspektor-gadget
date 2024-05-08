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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func TestWasmFields(t *testing.T) {
	type field struct {
		name string
		typ  api.Kind
		acc  datasource.FieldAccessor
		val  any
	}

	// fields added by the wasm module
	fields := []*field{
		//{"field_bool", api.Kind_Bool},
		{"field_int8", api.Kind_Int8, nil, int8(-123)},
		{"field_int16", api.Kind_Int16, nil, int16(-25647)},
		{"field_int32", api.Kind_Int32, nil, int32(-535245564)},
		{"field_int64", api.Kind_Int64, nil, int64(-1234567890)},
		{"field_uint8", api.Kind_Uint8, nil, uint8(56)},
		{"field_uint16", api.Kind_Uint16, nil, uint16(12345)},
		{"field_uint32", api.Kind_Uint32, nil, uint32(1234567890)},
		{"field_uint64", api.Kind_Uint64, nil, uint64(1234567890123456)},
		{"field_float32", api.Kind_Float32, nil, float32(3.14159)},
		{"field_float64", api.Kind_Float64, nil, float64(3.14159265359)},
		{"field_string", api.Kind_String, nil, string("Hello, World!")},
		{"field_bytes", api.Kind_Bytes, nil, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	}

	counter := 0

	const opPriority = 50000
	myOperator := simple.New("myHandler", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		datasources := gadgetCtx.GetDataSources()
		myds, ok := datasources["myds"]
		if !ok {
			return fmt.Errorf("datasource not found")
		}

		for _, f := range fields {
			f.acc = myds.GetField(f.name)
			if f.acc == nil {
				return fmt.Errorf("field %q not found", f.name)
			}

			if f.acc.Type() != f.typ {
				return fmt.Errorf("bad field type: %s vs %s", f.acc.Type(), f.typ)
			}
		}

		myds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
			counter++

			// We only need to process a single event!
			if counter > 1 {
				return nil
			}

			// Check that fields set by the wasm program are correct
			for _, f := range fields {
				switch f.typ {
				case api.Kind_Int8:
					val := f.acc.Int8(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Int16:
					val := f.acc.Int16(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Int32:
					val := f.acc.Int32(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Int64:
					val := f.acc.Int64(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Uint8:
					val := f.acc.Uint8(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Uint16:
					val := f.acc.Uint16(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Uint32:
					val := f.acc.Uint32(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Uint64:
					val := f.acc.Uint64(data)
					assert.Equal(t, f.val, val)
				//case api.Kind_Float32:
				//	val := f.acc.Float32(data)
				//	assert.Equal(t, f.val, val)
				//case api.Kind_Float64:
				//	val := f.acc.Float64(data)
				//	assert.Equal(t, f.val, val)
				case api.Kind_String:
					val := f.acc.String(data)
					assert.Equal(t, f.val, val)
				case api.Kind_Bytes:
					val := f.acc.Bytes(data)
					assert.Equal(t, f.val, val)
				}
			}
			return nil
		}, opPriority)
		return nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	t.Cleanup(cancel)

	gadgetCtx := gadgetcontext.New(
		ctx,
		"wasm:latest",
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, myOperator),
	)

	// Register data source that will be used by the wasm program to add fields
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeEvent, "myds")
	require.NoError(t, err, "registering datasource")

	hostF, err := ds.AddField("host_field", api.Kind_String)
	require.NoError(t, err, "adding field")

	fields = append(fields, &field{
		name: "host_field",
		typ:  api.Kind_String,
		acc:  hostF,
		val:  "LOCALHOST",
	},
	)

	go func() {
		for {
			data := ds.NewData()
			// TODO: PutString missing
			err := ds.EmitAndRelease(data)
			require.NoError(t, err, "emitting data")

			time.Sleep(100 * time.Millisecond)
		}
	}()

	runtime := local.New()
	err = runtime.Init(nil)
	require.NoError(t, err, "runtime init")
	t.Cleanup(func() { runtime.Close() })

	params := map[string]string{
		"operator.oci.verify-image": "false",
	}
	err = runtime.RunGadget(gadgetCtx, nil, params)
	require.NoError(t, err, "running gadget")

	// We need to be sure we processed as least one event
	require.NotZero(t, counter, "counter is zero")
}
