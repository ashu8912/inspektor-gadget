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

package api

import (
	"fmt"
	"runtime"
)

//go:wasmimport env newDataSource
func newDataSource(name uint64) uint32

//go:wasmimport env getDataSource
func getDataSource(name uint64) uint32

//go:wasmimport env dataSourceSubscribe
func dataSourceSubscribe(ds uint32, prio uint32, cb uint64)

//go:wasmimport env dataSourceGetField
func dataSourceGetField(ds uint32, name uint64) uint32

//go:wasmimport env dataSourceAddField
func dataSourceAddField(ds uint32, name uint64, kind uint32) uint32

//go:wasmimport env dataSourceNewData
func dataSourceNewData(ds uint32) uint32

//go:wasmimport env dataSourceEmitAndRelease
func dataSourceEmitAndRelease(ds uint32, data uint32) uint32

//go:wasmimport env dataSourceRelease
func dataSourceRelease(ds uint32, data uint32)

var (
	dsSubscriptionCtr = uint64(0)
	dsSubcriptions    = map[uint64]func(DataSource, Data){}
)

//export dsCallback
func dsCallback(cbID uint64, ds uint32, data uint32) {
	cb, ok := dsSubcriptions[cbID]
	if !ok {
		return
	}
	cb(DataSource(ds), Data(data))
}

type (
	DataSource uint32
	Field      uint32
	Data       uint32
)

func GetDataSource(name string) (DataSource, error) {
	ret := getDataSource(uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("datasource %s not found", name)
	}
	return DataSource(ret), nil
}

func NewDataSource(name string) (DataSource, error) {
	ret := newDataSource(uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("error creating datasource %q", name)
	}
	return DataSource(ret), nil
}

func (ds DataSource) Subscribe(cb func(DataSource, Data), priority uint32) {
	dsSubscriptionCtr++
	dsSubcriptions[dsSubscriptionCtr] = cb
	dataSourceSubscribe(uint32(ds), priority, dsSubscriptionCtr)
}

func (ds DataSource) NewData() Data {
	return Data(dataSourceNewData(uint32(ds)))
}

func (ds DataSource) EmitAndRelease(data Data) error {
	ret := dataSourceEmitAndRelease(uint32(ds), uint32(data))
	if ret != 0 {
		return fmt.Errorf("error emitting data")
	}
	return nil
}

func (ds DataSource) Release(data Data) {
	dataSourceRelease(uint32(ds), uint32(data))
}

func (ds DataSource) GetField(name string) (Field, error) {
	ret := dataSourceGetField(uint32(ds), uint64(stringToBufPtr(name)))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("field %q not found", name)
	}
	return Field(ret), nil
}

func (ds DataSource) AddField(name string, kind FieldKind) (Field, error) {
	ret := dataSourceAddField(uint32(ds), uint64(stringToBufPtr(name)), uint32(kind))
	runtime.KeepAlive(name)
	if ret == 0 {
		return 0, fmt.Errorf("error adding field %q", name)
	}
	return Field(ret), nil
}

type FieldKind uint32

const (
	Kind_Invalid FieldKind = 0
	Kind_Bool    FieldKind = 1
	Kind_Int8    FieldKind = 2
	Kind_Int16   FieldKind = 3
	Kind_Int32   FieldKind = 4
	Kind_Int64   FieldKind = 5
	Kind_Uint8   FieldKind = 6
	Kind_Uint16  FieldKind = 7
	Kind_Uint32  FieldKind = 8
	Kind_Uint64  FieldKind = 9
	Kind_Float32 FieldKind = 10
	Kind_Float64 FieldKind = 11
	Kind_String  FieldKind = 12
	Kind_CString FieldKind = 13
	Kind_Bytes   FieldKind = 14
)
