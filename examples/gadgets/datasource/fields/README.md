# Getting Specific Fields from a `datasource`

This example shows how to get some specific fields from the event by using the
data source.

### How to compile

```bash
$ go build .
```

### How to run

The compiled binary doesn't need any parameters, just run it with root permissions:

```bash
$ sudo ./fields
```

In another terminal, open some files

```bash
$ cat /dev/null
```

Those will be printed in the gadget's terminal:

```bash
$ sudo ./fields
...
command cat (143535) opened /etc/ld.so.cache
command cat (143535) opened /lib/x86_64-linux-gnu/libc.so.6
command cat (143535) opened /usr/lib/locale/locale-archive
command cat (143535) opened /dev/null
...
```
