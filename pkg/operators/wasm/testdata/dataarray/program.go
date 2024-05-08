package main

import "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm/api"

//export init
func gadgetInit() int {
	ds, err := api.GetDataSource("myds")
	if err != nil {
		api.Warnf("failed to get datasource: %v", err)
		return 1
	}

	fooF, err := ds.GetField("foo")
	if err != nil {
		api.Warnf("failed to get host field: %v", err)
		return 1
	}

	err = ds.SubscribeArray(func(source api.DataSource, dataArray api.DataArray) error {
		l := dataArray.Len()
		if l != 10 {
			api.Warnf("bad length: got: %d, expected: 10", l)
			panic("bad length")
		}

		// Update value of first 10 elements
		for i := 0; i < 10; i++ {
			data := dataArray.Get(i)
			val, err := fooF.Uint32(data)
			if err != nil {
				api.Warnf("failed to get field: %v", err)
				panic("failed to get field")
			}
			fooF.SetUint32(data, val*uint32(i))
		}

		// Add 5 additional elements
		for i := 10; i < 15; i++ {
			data := dataArray.New()
			fooF.SetUint32(data, 424143*uint32(i))
			dataArray.Append(data)
		}

		return nil
	}, 0)

	if err != nil {
		api.Warnf("failed to subscribe: %v", err)
		return 1
	}

	return 0
}

func main() {}
