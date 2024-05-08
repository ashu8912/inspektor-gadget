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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (i *wasmOperatorInstance) addFieldFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "fieldAccessorGet", i.fieldAccessorGet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // Value
	)

	exportFunction(env, "fieldAccessorSet", i.fieldAccessorSet,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Accessor
			wapi.ValueTypeI32, // Data
			wapi.ValueTypeI32, // Kind
			wapi.ValueTypeI64, // Value
		},
		[]wapi.ValueType{},
	)
}

// fieldAccessorGet returns the field's value.
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// Return value:
// - Uint64 representation of the value of the field, depending on the type
// requested, or a pointer
func (i *wasmOperatorInstance) fieldAccessorGet(ctx context.Context, m wapi.Module, stack []uint64) {
	acc, ok := i.getHandle(wapi.DecodeU32(stack[0])).(datasource.FieldAccessor)
	if !ok {
		i.logger.Warnf("field handle %d not found", stack[0])
		stack[0] = 0
		return
	}
	data, ok := i.getHandle(wapi.DecodeU32(stack[1])).(datasource.Data)
	if !ok {
		i.logger.Warnf("data handle %d not found", stack[1])
		stack[0] = 0
		return
	}

	handleBytes := func(buf []byte) uint64 {
		res, err := i.guestMalloc.Call(ctx, uint64(len(buf)))
		if err != nil {
			i.logger.Warnf("malloc failed: %v", err)
			return 0

		}

		if !m.Memory().Write(uint32(res[0]), buf) {
			i.logger.Warnf("out of memory write")
			return 0
		}

		return uint64(len(buf))<<32 | uint64(res[0])
	}

	switch api.Kind(stack[2]) {
	case api.Kind_Int8:
		stack[0] = uint64(acc.Int8(data))
	case api.Kind_Int16:
		stack[0] = uint64(acc.Int16(data))
	case api.Kind_Int32:
		stack[0] = uint64(acc.Int32(data))
	case api.Kind_Int64:
		stack[0] = uint64(acc.Int64(data))
	case api.Kind_Uint8:
		stack[0] = uint64(acc.Uint8(data))
	case api.Kind_Uint16:
		stack[0] = uint64(acc.Uint16(data))
	case api.Kind_Uint32:
		stack[0] = uint64(acc.Uint32(data))
	case api.Kind_Uint64:
		stack[0] = uint64(acc.Uint64(data))
	case api.Kind_Float32:
		stack[0] = uint64(acc.Float32(data))
	case api.Kind_Float64:
		stack[0] = uint64(acc.Float64(data))
	// These are a bit special as they don't fit in the return value, so we have to
	// allocate an array in the guest memory and return a pointer to it.
	case api.Kind_String:
		stack[0] = handleBytes([]byte(acc.String(data)))
	case api.Kind_Bytes:
		stack[0] = handleBytes(acc.Bytes(data))
	default:
		i.logger.Warnf("unknown field kind: %d", stack[2])
		stack[0] = 0
	}
}

// fieldAccessorSet sets the field's value
// Params:
// - stack[0]: Field handle
// - stack[1]: Data handle
// - stack[2]: Kind
// - stack[3]: Value to store
func (i *wasmOperatorInstance) fieldAccessorSet(ctx context.Context, m wapi.Module, stack []uint64) {
	acc, ok := i.getHandle(wapi.DecodeU32(stack[0])).(datasource.FieldAccessor)
	if !ok {
		i.logger.Warnf("field handle %d not found", stack[0])
		stack[0] = 0
		return
	}
	data, ok := i.getHandle(wapi.DecodeU32(stack[1])).(datasource.Data)
	if !ok {
		i.logger.Warnf("data handle %d not found", stack[1])
		stack[0] = 0
		return
	}

	switch api.Kind(stack[2]) {
	case api.Kind_Int8:
		acc.Set(data, make([]byte, 1))
		acc.PutInt8(data, int8(stack[3]))
	case api.Kind_Int16:
		acc.Set(data, make([]byte, 2))
		acc.PutInt16(data, int16(stack[3]))
	case api.Kind_Int32:
		acc.Set(data, make([]byte, 4))
		acc.PutInt32(data, int32(stack[3]))
	case api.Kind_Int64:
		acc.Set(data, make([]byte, 8))
		acc.PutInt64(data, int64(stack[3]))
	case api.Kind_Uint8:
		acc.Set(data, make([]byte, 1))
		acc.PutUint8(data, uint8(stack[3]))
	case api.Kind_Uint16:
		acc.Set(data, make([]byte, 2))
		acc.PutUint16(data, uint16(stack[3]))
	case api.Kind_Uint32:
		acc.Set(data, make([]byte, 4))
		acc.PutUint32(data, uint32(stack[3]))
	case api.Kind_Uint64:
		acc.Set(data, make([]byte, 8))
		acc.PutUint64(data, uint64(stack[3]))
	case api.Kind_String:
		str, err := stringFromStack(m, stack[3])
		if err != nil {
			i.logger.Warnf("reading string from stack: %v", err)
			stack[0] = 0
			return
		}

		// TODO: this hacky workaround is to allow set fixed-size strings.
		// Without this, the operation fails as the string is not the expected size.
		// This should be handled in the setter itself
		buf := []byte(str)

		// fill the string with 0s if it's a static field
		s := acc.Size()
		if s != 0 {
			if len(buf) > int(s) {
				i.logger.Warnf("string too long: %d > %d", len(buf), s)
				stack[0] = 0
				return
			}

			buf = append(buf, make([]byte, int(s)-len(buf))...)
		}

		if err := acc.Set(data, buf); err != nil {
			i.logger.Warnf("setting string failed: %v", err)
			stack[0] = 0
			return
		}
	case api.Kind_Bytes:
		buf, err := bufFromStack(m, stack[3])
		if err != nil {
			i.logger.Warnf("reading bytes from stack: %v", err)
			stack[0] = 0
			return
		}

		acc.PutBytes(data, buf)
	default:
		i.logger.Warnf("unknown field kind: %d", uint32(stack[2]))
		stack[0] = 0
	}
}
