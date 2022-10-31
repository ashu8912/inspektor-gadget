// Copyright 2022 The Inspektor Gadget authors
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

package sort

import (
	"reflect"
	"sort"

	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

type columnSorter[T any] struct {
	column *columns.Column[T]
	order  columns.Order
}

type ColumnSorterCollection[T any] struct {
	sorters []*columnSorter[T]
}

func (csc *ColumnSorterCollection[T]) Sort(entries []*T) {
	if len(entries) == 0 {
		return
	}

	for _, s := range csc.sorters {
		var sortFunc func(i, j int) bool
		offs := s.column.GetOffset()
		order := s.order

		switch s.column.Kind() {
		case reflect.Int:
			sortFunc = getLessFunc[int, T](entries, offs, order)
		case reflect.Int8:
			sortFunc = getLessFunc[int8, T](entries, offs, order)
		case reflect.Int16:
			sortFunc = getLessFunc[int16, T](entries, offs, order)
		case reflect.Int32:
			sortFunc = getLessFunc[int32, T](entries, offs, order)
		case reflect.Int64:
			sortFunc = getLessFunc[int64, T](entries, offs, order)
		case reflect.Uint:
			sortFunc = getLessFunc[uint, T](entries, offs, order)
		case reflect.Uint8:
			sortFunc = getLessFunc[uint8, T](entries, offs, order)
		case reflect.Uint16:
			sortFunc = getLessFunc[uint16, T](entries, offs, order)
		case reflect.Uint32:
			sortFunc = getLessFunc[uint32, T](entries, offs, order)
		case reflect.Uint64:
			sortFunc = getLessFunc[uint64, T](entries, offs, order)
		case reflect.Float32:
			sortFunc = getLessFunc[float32, T](entries, offs, order)
		case reflect.Float64:
			sortFunc = getLessFunc[float64, T](entries, offs, order)
		case reflect.String:
			sortFunc = getLessFunc[string, T](entries, offs, order)
		default:
			continue
		}

		sort.SliceStable(entries, sortFunc)
	}
}

// Prepare prepares a sorter collection that can be re-used for multiple calls to Sort() for efficiency. Filter rules
// will be applied from right to left (first rule has the highest priority).
func Prepare[T any](cols columns.ColumnMap[T], sortBy []string) *ColumnSorterCollection[T] {
	sorters := make([]*columnSorter[T], 0, len(sortBy))
	for i := len(sortBy) - 1; i >= 0; i-- {
		sortField := sortBy[i]

		if len(sortField) == 0 {
			continue
		}

		// Handle ordering
		order := columns.OrderAsc
		if sortField[0] == '-' {
			sortField = sortField[1:]
			order = columns.OrderDesc
		}

		column, ok := cols.GetColumn(sortField)
		if !ok {
			continue
		}

		sorters = append(sorters, &columnSorter[T]{
			column: column,
			order:  order,
		})
	}
	return &ColumnSorterCollection[T]{
		sorters: sorters,
	}
}

// SortEntries sorts entries by applying the sortBy rules from right to left (first rule has the highest
// priority). The rules are strings containing the column names, optionally prefixed with "-" to switch to descending
// sort order.
func SortEntries[T any](cols columns.ColumnMap[T], entries []*T, sortBy []string) {
	if entries == nil {
		return
	}

	coll := Prepare(cols, sortBy)
	coll.Sort(entries)
}

func getLessFunc[OT constraints.Ordered, T any](array []*T, offs uintptr, order columns.Order) func(i, j int) bool {
	return func(i, j int) bool {
		if array[i] == nil {
			return false
		}
		if array[j] == nil {
			return true
		}
		return !(columns.GetField[OT](array[i], offs) < columns.GetField[OT](array[j], offs)) != order
	}
}
