// Copyright 2023-2024 The Inspektor Gadget authors
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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gadgetservice "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func newDaemonCommand(runtime runtime.Runtime) *cobra.Command {
	daemonCmd := &cobra.Command{
		Use:          "daemon",
		Short:        "Run Inspektor Gadget as a daemon",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}

	var socket string
	var group string
	var eventBufferLength uint64
	var serverKey string
	var serverCert string
	var clientCA string

	daemonCmd.PersistentFlags().StringVarP(
		&group,
		"group",
		"G",
		"0",
		"Group name or id that the unix socket should use (if daemon-socket is set to e.g. unix:///path/to.socket)")

	daemonCmd.PersistentFlags().StringVarP(
		&socket,
		"host",
		"H",
		api.DefaultDaemonPath,
		"The socket to listen on for new requests. Can be a unix socket"+
			" (unix:///path/to.socket) or a tcp socket (tcp://127.0.0.1:1234)")

	daemonCmd.PersistentFlags().Uint64VarP(
		&eventBufferLength,
		"events-buffer-length",
		"",
		16384,
		"The events buffer length. A low value could impact horizontal scaling.")

	daemonCmd.PersistentFlags().StringVarP(
		&serverKey,
		"tls-key",
		"",
		"",
		"Path to tls key file")

	daemonCmd.PersistentFlags().StringVarP(
		&serverCert,
		"tls-cert",
		"",
		"",
		"Path to tls cert file")

	daemonCmd.PersistentFlags().StringVarP(
		&clientCA,
		"tls-client-ca",
		"",
		"",
		"Path to CA certificate for client validation")

	daemonCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("%s must be run as root to be able to run eBPF programs", filepath.Base(os.Args[0]))
		}

		socketType, socketPath, err := api.ParseSocketAddress(socket)
		if err != nil {
			return fmt.Errorf("invalid daemon-socket address: %w", err)
		}

		gid := 0
		if tmpGroup, err := user.LookupGroup(group); err == nil {
			gid, err = strconv.Atoi(tmpGroup.Gid)
			if err != nil {
				return fmt.Errorf("unexpected non-numeric group id %q for group %q", tmpGroup.Gid, group)
			}
		} else if tmpGid, err := strconv.Atoi(group); err == nil {
			gid = tmpGid
		} else {
			return fmt.Errorf("group %q not found", group)
		}

		log.Infof("starting Inspektor Gadget daemon at %q", socket)
		service := gadgetservice.NewService(log.StandardLogger(), eventBufferLength)

		var options []grpc.ServerOption

		if serverKey != "" || serverCert != "" || clientCA != "" {
			cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
			if err != nil {
				return fmt.Errorf("loading TLS keypair: %w", err)
			}

			ca := x509.NewCertPool()
			caBytes, err := os.ReadFile(clientCA)
			if err != nil {
				return fmt.Errorf("loading client CA certificate: %w", err)
			}

			if ok := ca.AppendCertsFromPEM(caBytes); !ok {
				return errors.New("failed to parse client CA certificate")
			}

			tlsConfig := &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{cert},
				ClientCAs:    ca,
			}

			options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))
		} else {
			log.Warnf("no TLS configuration provided, running in insecure mode")
		}

		return service.Run(gadgetservice.RunConfig{
			SocketType: socketType,
			SocketPath: socketPath,
			SocketGID:  gid,
		}, options...)
	}

	return daemonCmd
}
