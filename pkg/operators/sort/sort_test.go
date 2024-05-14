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

package sort

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func Tester(
	t *testing.T,
	operator operators.DataOperator,
	paramValues api.ParamValues,
	prepare func(operators.GadgetContext) error,
	produce func(operators.GadgetContext) error,
	verify func(operators.GadgetContext) error,
) {
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
		simple.OnStop(func(gadgetCtx operators.GadgetContext) error {
			// Remove me once OnStop in SimpleOperator is fixed
			return nil
		}),
	)

	verifier := simple.New("verifier",
		simple.WithPriority(Priority+1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			defer wg.Done()
			defer cancel()
			return verify(gadgetCtx)
		}),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(operator, producer, verifier))

	err := gadgetCtx.Run(paramValues)
	assert.NoError(t, err)
}

func SortTester(
	t *testing.T,
	fieldTypes []api.Kind,
	fieldNames []string,
	valuesIn [][]any,
	valuesOut [][]any,
	param string,
	setterFunc func(datasource.Data, datasource.FieldAccessor, any),
	compareFunc func(*testing.T, datasource.Data, datasource.FieldAccessor, any),
) {
	Tester(
		t,
		Operator,
		api.ParamValues{
			"operator.sort.sort": param,
		},
		func(gadgetCtx operators.GadgetContext) error {
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, "foo")
			assert.NoError(t, err)

			for i, fieldName := range fieldNames {
				_, err = ds.AddField(fieldName, fieldTypes[i], datasource.WithTags("sorter:"+fieldName))
				assert.NoError(t, err)
			}
			return nil
		},
		func(gadgetCtx operators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				if ds.Type() != datasource.TypeArray {
					continue
				}

				arr, _ := ds.NewPacketArray()
				for i := 0; i < len(valuesIn); i++ {
					data := arr.New()
					for fi, fieldName := range fieldNames {
						field := ds.GetFieldsWithTag("sorter:" + fieldName)[0]
						setterFunc(data, field, valuesIn[i][fi])
					}
					arr.Append(data)
				}

				err := ds.EmitAndRelease(arr)
				assert.NoError(t, err)
			}
			return nil
		},
		func(gadgetCtx operators.GadgetContext) error {
			for _, s := range gadgetCtx.GetDataSources() {
				if s.Type() != datasource.TypeArray {
					continue
				}
				s.SubscribeArray(func(ds datasource.DataSource, array datasource.DataArray) error {
					assert.Equal(t, array.Len(), len(valuesOut))

					for i := 0; i < len(valuesOut); i++ {
						data := array.Get(i)
						for fi, fieldName := range fieldNames {
							field := ds.GetFieldsWithTag("sorter:" + fieldName)[0]
							compareFunc(t, data, field, valuesOut[i][fi])
						}
					}

					ds.Dump(array.(datasource.PacketArray), os.Stdout)

					return nil
				}, Priority+1)
			}
			return nil
		},
	)
}

func TestNumbers(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint32},
		[]string{"number"},
		[][]any{{5}, {4}, {3}, {2}, {1}},
		[][]any{{1}, {2}, {3}, {4}, {5}},
		"number",
		func(data datasource.Data, field datasource.FieldAccessor, a any) {
			switch field.Name() {
			case "number":
				field.Set(data, []byte{0, 0, 0, 0})
				field.PutUint32(data, uint32(a.(int)))
			}
		},
		func(t *testing.T, data datasource.Data, field datasource.FieldAccessor, a any) {
			switch field.Name() {
			case "number":
				v, _ := field.Uint32(data)
				assert.Equal(t, uint32(a.(int)), v)
			}
		},
	)
}

func TestNumbersDesc(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_Uint32},
		[]string{"number"},
		[][]any{{1}, {3}, {2}, {5}, {4}},
		[][]any{{5}, {4}, {3}, {2}, {1}},
		"-number",
		func(data datasource.Data, field datasource.FieldAccessor, a any) {
			switch field.Name() {
			case "number":
				field.Set(data, []byte{0, 0, 0, 0})
				field.PutUint32(data, uint32(a.(int)))
			}
		},
		func(t *testing.T, data datasource.Data, field datasource.FieldAccessor, a any) {
			switch field.Name() {
			case "number":
				v, _ := field.Uint32(data)
				assert.Equal(t, uint32(a.(int)), v)
			}
		},
	)
}

func TestStrings(t *testing.T) {
	SortTester(
		t,
		[]api.Kind{api.Kind_String},
		[]string{"string"},
		[][]any{{"mno"}, {"ghi"}, {"abc"}, {"def"}, {"jkl"}},
		[][]any{{"abc"}, {"def"}, {"ghi"}, {"jkl"}, {"mno"}},
		"string",
		func(data datasource.Data, field datasource.FieldAccessor, a any) {
			switch field.Name() {
			case "string":
				field.Set(data, []byte(a.(string)))
			}
		},
		func(t *testing.T, data datasource.Data, field datasource.FieldAccessor, a any) {
			switch field.Name() {
			case "string":
				v, _ := field.String(data)
				assert.Equal(t, a.(string), v)
			}
		},
	)
}
