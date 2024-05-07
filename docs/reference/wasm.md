---
title: 'wasm'
weight: 110
description: 'Wasm API exposed to guests'
---

Inspektor Gadget exposes some functions to wasm modules implemented in gadgets.
We provide a Golang wrapper for this functionality, but these functions can be
used directly from any programming language that can be compiled to wasm.

## Data types

Data types passed to the API are encoded using 64 bits. Primitive types like
integers, booleans and floats are casted directly to 64 bits integer and passed
using the stack.

Strings and byte arrays are stored in the wasm module's memory. A 64 bits
integer is used to represent a pointer to them, the higher 32 bits contains the
length and the lower 32 the memory address.

## API

### Log

####  `gadgetLog(u32 level, string msg)`

Print a log message using the gadget's logger instance.

Parameters:

- `level` (u32): Log level:
  - 0: Error
  - 1: Warn
  - 2: Info
  - 3: Debug
  - 4: Trace
- `msg` (string): Message to print

Return value:
- None

### Datasources

#### `newDataSource(string name)`

Creates a new data source.

Parameters:
- `name` (string): Datasource's name

Return value:
- (u32): Handle to the created data source, 0 in case of error.

#### `getDataSource(string name) u32`

Get a handle to a data source.

Parameters:
- `name` (string): Datasource's name

Return value:
- (u32) Handle to the data source, 0 in case of error.

#### `dataSourceSubscribe(u32 ds, u32 type, u32 prio, u64 cb)`

Subscribe to events emitted by a data source.

This mechanism requires the wasm module to export a `dsCallback` that is called
by the host when an event is emitted:

`dsCallback(u64 cbID, u32 ds, u32 data)`
- `cbID`: Callback ID
- `ds`: Datasource handle
- `data`: Data handle


Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `type` (u32): Subscription type: (0: Data, 1: Array, 2: Packet)
- `priotity` (u32): Priority of the subscription. Lower means higher priority.
- `cb` (u64): Callback ID passed to `dsCallback`

Return value:
- 0 on sucess, 1 in case of error.

#### `dataSourceGetField(u32 ds, string name) u32`

Get a field from a datasource

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `name`(string): Field's name

Return value:
- (u32): Field handle, 0 in case of error.

#### `dataSourceAddField(u32 ds, string name, u32 kind) u32`

Add a field to a data source

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `name`(string): Field's name
- `kind` (u32): Field's kind. See values in https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget@main/pkg/gadget-service/api#Kind.

Return value:
- (u32): Field handle, 0 in case of error.

#### `dataSourceNewPacketSingle(u32 ds) u32`

Allocate a packet instance. The returned packet has to be released with
`dataSourceEmitAndRelease` or `dataSourceRelease`.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- (u32): Packet handle

#### `dataSourceNewPacketArray(u32 ds) u32`

Allocate a packet array instance. The returned packet has to be released with
`dataSourceEmitAndRelease` or `dataSourceRelease`.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)

Return value:
- (u32): Packet handle


#### `dataSourceEmitAndRelease(u32 ds, u32 data) u32`

Emit and release a packet instance.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `data` (u32): Packet handle (as returned by `dataSourceNewPacketSingle`)

Return value:
- 0 in case of success, 1 otherwise.

#### `dataSourceRelease(u32 ds, u32 data)`

Release a packet instance without sending it.

Parameters:
- `ds` (u32): Datasource handle (as returned by `getDataSource` or `newDataSource`)
- `data` (u32): Packet handle (as returned by `dataSourceNewPacketSingle`)

Return value:
- None

### Fields

#### `fieldAccessorGet(u32 acc, u32 data, u32 kind) u64`

Get the value of a field.

Parameters:
- `acc` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `data` (u32): Data handle
- `kind` (u32): Kind of access: How to read the field.

Return value:
- Value of the field.

#### `fieldAccessorSet(u32 acc, u32 data, u32 kind, u64 value)`

Set the value of a field.

Parameters:
- `acc` (u32): Field handle (as returned by `dataSourceGetField` or `dataSourceAddField`)
- `data` (u32): Data handle
- `kind` (u32): Kind of access: How to write the field
  `value` (u64): Value to store in the field

Return value:
- None
