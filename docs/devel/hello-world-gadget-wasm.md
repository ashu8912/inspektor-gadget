---
title: Hello world gadget with wasm module
weight: 120
description: >
  Hello world gadget with wasm module
---

> [!WARNING]
> This feature is experimental. To activate the commands, you must set the `IG_EXPERIMENTAL` environment variable to `true`.
>
> ```bash
> $ export IG_EXPERIMENTAL=true
> ```

This guide explores the wasm support to implement complex logic in our gadget.
This is a continuation of [hello world gadget](./hello-world-gadget.md), be sure
to follow that one before.

### Creating our first wasm program

Create a `program.go` file in the same folder of the `program.bpf.c` one. As a
first step, let's define the `init`, `start` and `stop` functions and emit some
log messages from them:

```golang
package main

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm/api"
)

//export init
func gadgetInit() int {
	api.Info("init: hello from wasm")
	return 0
}

//export start
func gadgetStart() int {
	api.Info("start: hello from wasm")
	return 0
}

//export stop
func gadgetStop() int {
	api.Info("stop: hello from wasm")
	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}
```

We also need a `build.yaml` file that indicates the gadget includes a Golang
program that needs to be compiled to a wasm module:

```yaml
wasm: program.go
```

Build the gadget

```bash
$ sudo -E ig image build . -t mygadget:wasm
```

and run it:

```bash
$ sudo -E ig run mygadget:wasm --verify-image=false
INFO[0000] Experimental features enabled
WARN[0000] you set --verify-image=false, image will not be verified
INFO[0000] init: hello from wasm
WARN[0000] you set --verify-image=false, image will not be verified
INFO[0000] init: hello from wasm
RUNTIME.CONTAINERNAME        MNTNS_ID            PID            COMM           FILENAME
INFO[0001] start: hello from wasm
...
^CINFO[0009] stop: hello from wasm
```

You can see how the different messages coming from wasm are printed in the
terminal.

### Manipulating fields

Now let's do something more interesting. Let's suppose we want to refact the
user name in the path of the file. Manipulating strings in eBPF is usually
complicated, leave aside using regular expressions.

Our goal is to look for strings like `/home/<user-name>/...` and redact (replace
by `***`) the user name part.

This can be done by using a regular expression (i.e. asking ChatGPT to generate
one because nobody understands them).

This is how the `gadgetInit` function looks now:

```golang
//export init
func gadgetInit() int {
	api.Info("init: hello from wasm")

	// Get the "open" datasource (name used in the GADGET_TRACER macro)
	ds, err := api.GetDataSource("open")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	// Get the field we're interested in
	filenameF, err := ds.GetField("filename")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	pattern := regexp.MustCompile(`^(/home/)(.*?)/(.*)$`)

	// Subscribe to all events from "open" so we manipulate the data in the callback
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		fileName := filenameF.String(data)
		replaced := pattern.ReplaceAllString(fileName, "${1}***/${3}")
		filenameF.SetString(data, replaced)
	}, 0)

	return 0
}
```

Build and run the gadget again:

```bash
$ sudo -E ig image build . -t mygadget:wasm
...


$ sudo -E ig run mygadget:wasm --verify-image=false
INFO[0000] Experimental features enabled
WARN[0000] you set --verify-image=false, image will not be verified
INFO[0000] init: hello from wasm
WARN[0000] you set --verify-image=false, image will not be verified
INFO[0000] init: hello from wasm
RUNTIME.CONTAINERNAME        MNTNS_ID            PID            COMM           FILENAME
INFO[0001] start: hello from wasm
```

Let's generate some events from a container:

```bash
$ docker run --name c3 --rm -it busybox sh

# inside the cotainer:
$ mkdir /home/mvb
$ touch /home/mvb/xxx.txt
$ cat /home/mvb/xxx.txt
```

The gadget redacts the user name as expected:

```bash
RUNTIME.CONTAINERNAME        MNTNS_ID            PID            COMM           FILENAME
c3                           4026534569          226136         cat            /home/***/xxx.txt
```

### Adding new fields

There are cases where we want to add new fields from wasm. For instance, let's
add a field that contains a human readable representation of the event.

The `gadgetInit` functions now looks like:

```golang
//export init
func gadgetInit() int {
	api.Info("init: hello from wasm")

	// Get the "open" datasource (name used in the GADGET_TRACER macro)
	ds, err := api.GetDataSource("open")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	// Get the field we're interested in
	filenameF, err := ds.GetField("filename")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	pidF, err := ds.GetField("pid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	humanF, err := ds.AddField("human", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	pattern := regexp.MustCompile(`^(/home/)(.*?)/(.*)$`)

	// Subscribe to all events from "open" so we manipulate the data in the callback
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		fileName := filenameF.String(data)
		replaced := pattern.ReplaceAllString(fileName, "${1}***/${3}")
		filenameF.SetString(data, replaced)

		human := fmt.Sprintf("file %q was opened by %d", fileName, pidF.Uint32(data))
		humanF.SetString(data, human)
	}, 0)

	return 0
}
```

Build and run the gadget again. This time using `-o json` to easily see the
output from it:

```bash
$ sudo -E ig image build . -t mygadget:wasm
...

$ sudo -E ig run mygadget:wasm --verify-image=false -o jsonpretty
{
  "comm": "cat",
  "filename": "/home/***/xxx.txt",
  "human": "file '/home/mvb/xxx.txt' was opened by 121351",
  "k8s": {
    "container": "",
    "hostnetwork": false,
    "namespace": "",
    "node": "",
    "pod": ""
  },
  "mntns_id": 4026534661,
  "pid": 121351,
  "runtime": {
    "containerId": "2de33de4d1c73be918916322bf488a32f8b7a6eea0903422278fa13766e36f8f",
    "containerImageDigest": "",
    "containerImageName": "busybox",
    "containerName": "c3",
    "runtimeName": "docker"
  }
}
```

Notice how the human field is there when `cat /home/mvb/xxx.txt` is executed in
the container.

### Dropping events

TBD!
