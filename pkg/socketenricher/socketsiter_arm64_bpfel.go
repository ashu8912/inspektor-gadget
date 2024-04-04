// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package socketenricher

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type socketsiterBufT struct{ Buf [32768]uint8 }

type socketsiterSocketsKey struct {
	Netns  uint32
	Family uint16
	Proto  uint8
	_      [1]byte
	Port   uint16
	_      [2]byte
}

type socketsiterSocketsValue struct {
	Mntns             uint64
	PidTgid           uint64
	UidGid            uint64
	Task              [16]int8
	Pcomm             [16]int8
	Sock              uint64
	DeletionTimestamp uint64
	Cwd               [4096]uint8
	Exepath           [4096]uint8
	Ppid              uint32
	Ipv6only          int8
	_                 [3]byte
}

// loadSocketsiter returns the embedded CollectionSpec for socketsiter.
func loadSocketsiter() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SocketsiterBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load socketsiter: %w", err)
	}

	return spec, err
}

// loadSocketsiterObjects loads socketsiter and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*socketsiterObjects
//	*socketsiterPrograms
//	*socketsiterMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSocketsiterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSocketsiter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// socketsiterSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketsiterSpecs struct {
	socketsiterProgramSpecs
	socketsiterMapSpecs
}

// socketsiterSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketsiterProgramSpecs struct {
	IgSkCleanup *ebpf.ProgramSpec `ebpf:"ig_sk_cleanup"`
	IgSocketsIt *ebpf.ProgramSpec `ebpf:"ig_sockets_it"`
}

// socketsiterMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketsiterMapSpecs struct {
	Bufs          *ebpf.MapSpec `ebpf:"bufs"`
	GadgetSockets *ebpf.MapSpec `ebpf:"gadget_sockets"`
}

// socketsiterObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSocketsiterObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketsiterObjects struct {
	socketsiterPrograms
	socketsiterMaps
}

func (o *socketsiterObjects) Close() error {
	return _SocketsiterClose(
		&o.socketsiterPrograms,
		&o.socketsiterMaps,
	)
}

// socketsiterMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSocketsiterObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketsiterMaps struct {
	Bufs          *ebpf.Map `ebpf:"bufs"`
	GadgetSockets *ebpf.Map `ebpf:"gadget_sockets"`
}

func (m *socketsiterMaps) Close() error {
	return _SocketsiterClose(
		m.Bufs,
		m.GadgetSockets,
	)
}

// socketsiterPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSocketsiterObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketsiterPrograms struct {
	IgSkCleanup *ebpf.Program `ebpf:"ig_sk_cleanup"`
	IgSocketsIt *ebpf.Program `ebpf:"ig_sockets_it"`
}

func (p *socketsiterPrograms) Close() error {
	return _SocketsiterClose(
		p.IgSkCleanup,
		p.IgSocketsIt,
	)
}

func _SocketsiterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed socketsiter_arm64_bpfel.o
var _SocketsiterBytes []byte
