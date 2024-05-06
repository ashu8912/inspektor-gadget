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

// TODO: is it possible to make it work without cgo?

// #include <stdlib.h>
import "C"

import (
	"slices"
	"strings"
	"unsafe"
)

// bufPtr encodes the pointer and length of a buffer as a uint64
// The pointer is stored in the lower 32 bits and the length in the upper 32 bits
type bufPtr uint64

func (b bufPtr) free() {
	C.free(unsafe.Pointer(uintptr(b & 0xFFFFFFFF)))
}

// stringToBufPtr returns a bufPtr that encodes the pointer and length of the
// input string. Callers must use runtime.KeepAlive on the input string to
// ensure it is not garbage collected.
func stringToBufPtr(s string) bufPtr {
	unsafePtr := unsafe.Pointer(unsafe.StringData(s))
	return bufPtr(uint64(len(s))<<32 | uint64(uintptr(unsafePtr)))
}

// String returns the string stored in the buffer. The returned string isa copy.
// The buffer is released before returning.
func (b bufPtr) String() string {
	if b == 0 {
		return ""
	}
	// create a string that users the pointer as storage
	orig := unsafe.String((*byte)(unsafe.Pointer(uintptr(b&0xFFFFFFFF))), int(b>>32))
	// clone it
	ret := strings.Clone(orig)
	// free the original pointer
	b.free()
	// return the cloned string
	return ret
}

// bytesToBufPtr returns a bufPtr that encodes the pointer and length of the
// input buffer. Callers must use runtime.KeepAlive on the input buffer to
// ensure it is not garbage collected.
func bytesToBufPtr(b []byte) bufPtr {
	unsafePtr := unsafe.Pointer(unsafe.SliceData(b))
	return bufPtr(uint64(len(b))<<32 | uint64(uintptr(unsafePtr)))
}

// Bytes returns the bytes stored in the buffer. The returned slice is a copy.
// The buffer is released before returning.
func (b bufPtr) Bytes() []byte {
	if b == 0 {
		return nil
	}
	// create a slice that uses the pointer as storage
	orig := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(b&0xFFFFFFFF))), int(b>>32))
	// clone it
	ret := slices.Clone(orig)
	// free the original pointer
	b.free()
	// return the cloned string
	return ret
}
