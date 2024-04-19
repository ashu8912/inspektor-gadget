# `trace_open`

This example shows how to run the `trace_open` gadget and print the events it
captures to the terminal in json format.

### How to compile

```bash
$ go build .
```

### How to run

The compiled binary doesn't need any parameters, just run it with root permissions:

```bash
$ sudo ./trace_open
```

In another terminal, execute some processes (as root because others are filtered out)

```bash
$ sudo cat /dev/null
```

Those will be printed in the gadget's terminal:

```bash
$ sudo ./trace_open
{
  "comm": "cat",
  "err": 0,
  "fd": 3,
  "flags": 524288,
  "fname": "/usr/lib/locale/locale-archive",
  "gid": 0,
  "mntns_id": 4026531841,
  "mode": 0,
  "pid": 123229,
  "timestamp": 8350981866947,
  "uid": 0
}
{
  "comm": "cat",
  "err": 0,
  "fd": 3,
  "flags": 0,
  "fname": "/dev/null",
  "gid": 0,
  "mntns_id": 4026531841,
  "mode": 0,
  "pid": 123229,
  "timestamp": 8350981925488,
  "uid": 0
}
```
