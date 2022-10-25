// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package testdata

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tcpconnectDimensionsT struct {
	Saddr uint32
	Daddr uint32
}

// loadTcpconnect returns the embedded CollectionSpec for tcpconnect.
func loadTcpconnect() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TcpconnectBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tcpconnect: %w", err)
	}

	return spec, err
}

// loadTcpconnectObjects loads tcpconnect and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tcpconnectObjects
//	*tcpconnectPrograms
//	*tcpconnectMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTcpconnectObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTcpconnect()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tcpconnectSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnectSpecs struct {
	tcpconnectProgramSpecs
	tcpconnectMapSpecs
}

// tcpconnectSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnectProgramSpecs struct {
	TcpV4ConnectE *ebpf.ProgramSpec `ebpf:"tcp_v4_connect_e"`
	TcpV4ConnectX *ebpf.ProgramSpec `ebpf:"tcp_v4_connect_x"`
}

// tcpconnectMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnectMapSpecs struct {
	EventsHashCounter *ebpf.MapSpec `ebpf:"events_hash_counter"`
	EventsRingCounter *ebpf.MapSpec `ebpf:"events_ring_counter"`
	Sockets           *ebpf.MapSpec `ebpf:"sockets"`
}

// tcpconnectObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnectObjects struct {
	tcpconnectPrograms
	tcpconnectMaps
}

func (o *tcpconnectObjects) Close() error {
	return _TcpconnectClose(
		&o.tcpconnectPrograms,
		&o.tcpconnectMaps,
	)
}

// tcpconnectMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnectMaps struct {
	EventsHashCounter *ebpf.Map `ebpf:"events_hash_counter"`
	EventsRingCounter *ebpf.Map `ebpf:"events_ring_counter"`
	Sockets           *ebpf.Map `ebpf:"sockets"`
}

func (m *tcpconnectMaps) Close() error {
	return _TcpconnectClose(
		m.EventsHashCounter,
		m.EventsRingCounter,
		m.Sockets,
	)
}

// tcpconnectPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnectPrograms struct {
	TcpV4ConnectE *ebpf.Program `ebpf:"tcp_v4_connect_e"`
	TcpV4ConnectX *ebpf.Program `ebpf:"tcp_v4_connect_x"`
}

func (p *tcpconnectPrograms) Close() error {
	return _TcpconnectClose(
		p.TcpV4ConnectE,
		p.TcpV4ConnectX,
	)
}

func _TcpconnectClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed tcpconnect_bpfel_arm64.o
var _TcpconnectBytes []byte
