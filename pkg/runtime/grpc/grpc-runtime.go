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

package grpcruntime

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	gadgettls "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/tls"
)

type ConnectionMode int

const (
	// ConnectionModeDirect will connect directly to the remote using the gRPC protocol; the remote side can either
	// be a tcp or a unix socket endpoint
	ConnectionModeDirect ConnectionMode = iota

	// ConnectionModeKubernetesProxy will connect to a gRPC endpoint through a kubernetes API server by first looking
	// up an appropriate target node using the kubernetes API, then using the port forward
	// endpoint of the Kubernetes API to forward the gRPC connection to the service listener (see gadgettracermgr).
	ConnectionModeKubernetesProxy
)

const (
	ParamNode              = "node"
	ParamRemoteAddress     = "remote-address"
	ParamConnectionMethod  = "connection-method"
	ParamConnectionTimeout = "connection-timeout"
	ParamID                = "id"
	ParamDetach            = "detach"
	ParamTags              = "tags"
	ParamName              = "name"
	ParamEventBufferLength = "event-buffer-length"

	ParamTLSKey        = "tls-key-file"
	ParamTLSCert       = "tls-cert-file"
	ParamTLSServerCA   = "tls-server-ca-file"
	ParamTLSServerName = "tls-server-name"

	// ParamGadgetServiceTCPPort is only used in combination with KubernetesProxyConnectionMethodTCP
	ParamGadgetServiceTCPPort = "tcp-port"

	// ConnectTimeout is the time in seconds we wait for a connection to the remote to
	// succeed
	ConnectTimeout = 5

	// ResultTimeout is the time in seconds we wait for a result to return from the gadget
	// after sending a Stop command
	ResultTimeout = 30

	ParamGadgetNamespace   string = "gadget-namespace"
	DefaultGadgetNamespace string = "gadget"
)

type Runtime struct {
	info           *Info
	defaultValues  map[string]string
	globalParams   *params.Params
	restConfig     *rest.Config
	connectionMode ConnectionMode
}

type RunClient interface {
	Recv() (*api.GadgetEvent, error)
}

// New instantiates the runtime and loads the locally stored gadget info. If no info is stored locally,
// it will try to fetch one from one of the gadget nodes and store it locally. It will issue warnings on
// failures.
func New(options ...Option) *Runtime {
	r := &Runtime{
		defaultValues: map[string]string{},
	}
	for _, option := range options {
		option(r)
	}
	return r
}

func (r *Runtime) Init(runtimeGlobalParams *params.Params) error {
	if runtimeGlobalParams == nil {
		runtimeGlobalParams = r.GlobalParamDescs().ToParams()
	}

	// overwrite only if not yet initialized; for gadgetctl, this initialization happens
	// already in the main.go to specify a target address
	if r.globalParams == nil {
		r.globalParams = runtimeGlobalParams
	}
	return nil
}

func (r *Runtime) SetRestConfig(config *rest.Config) {
	r.restConfig = config
}

func (r *Runtime) Close() error {
	return nil
}

func checkForDuplicates(subject string) func(value string) error {
	return func(value string) error {
		values := strings.Split(value, ",")
		valueMap := make(map[string]struct{})
		for _, v := range values {
			if _, ok := valueMap[v]; ok {
				return fmt.Errorf("duplicate %s: %s", subject, v)
			}
			valueMap[v] = struct{}{}
		}
		return nil
	}
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	p := params.ParamDescs{}
	// Add params for headless mode
	p.Add(params.ParamDescs{
		{
			Key:          ParamDetach,
			Description:  "Create a headless gadget instance that will keep running in the background",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
			Tags:         []string{"!attach"},
		},
		{
			Key:         ParamTags,
			Description: "Comma-separated list of tags to apply to the gadget instance",
			TypeHint:    params.TypeString,
			Tags:        []string{"!attach"},
		},
		{
			Key:         ParamName,
			Description: "Distinctive name to assign to the gadget instance",
			TypeHint:    params.TypeString,
			Tags:        []string{"!attach"},
		},
		{
			Key:         ParamID,
			Description: "ID to assign to the gadget instance; if unset, it will be generated",
			TypeHint:    params.TypeString,
			Tags:        []string{"!attach"},
		},
		{
			Key:          ParamEventBufferLength,
			Description:  "Number of events to buffer on the server so they can be replayed when attaching; used with --detach; 0 = use server settings",
			TypeHint:     params.TypeInt,
			DefaultValue: "0",
			Tags:         []string{"!attach"},
		},
	}...)
	switch r.connectionMode {
	case ConnectionModeDirect:
		return p
	case ConnectionModeKubernetesProxy:
		p.Add(params.ParamDescs{
			{
				Key:         ParamNode,
				Description: "Comma-separated list of nodes to run the gadget on",
				Validator:   checkForDuplicates("node"),
			},
		}...)
		return p
	}
	panic("invalid connection mode set for grpc-runtime")
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	p := params.ParamDescs{
		{
			Key:          ParamConnectionTimeout,
			Description:  "Maximum time to establish a connection to remote target in seconds",
			DefaultValue: fmt.Sprintf("%d", ConnectTimeout),
			TypeHint:     params.TypeUint16,
		},
	}
	switch r.connectionMode {
	case ConnectionModeDirect:
		p.Add(params.ParamDescs{
			{
				Key:          ParamRemoteAddress,
				Description:  "Comma-separated list of remote address (gRPC) to connect to",
				DefaultValue: api.DefaultDaemonPath,
				Validator:    checkForDuplicates("address"),
			},
			{
				Key:         ParamTLSKey,
				Description: "TLS client key",
				TypeHint:    params.TypeString,
			},
			{
				Key:         ParamTLSCert,
				Description: "TLS client certificate",
				TypeHint:    params.TypeString,
			},
			{
				Key:         ParamTLSServerCA,
				Description: "TLS server CA certificate",
				TypeHint:    params.TypeString,
			},
			{
				Key:         ParamTLSServerName,
				Description: "override TLS server name (if omitted, using target server name)",
				TypeHint:    params.TypeString,
			},
		}...)
		return p
	case ConnectionModeKubernetesProxy:
		p.Add(params.ParamDescs{
			{
				Key:          ParamGadgetServiceTCPPort,
				Description:  "Port used to connect to the gadget service",
				DefaultValue: fmt.Sprintf("%d", api.GadgetServicePort),
				TypeHint:     params.TypeUint16,
			},
			{
				Key:          ParamGadgetNamespace,
				Description:  "Namespace where the Inspektor Gadget is deployed",
				DefaultValue: DefaultGadgetNamespace,
				TypeHint:     params.TypeString,
			},
		}...)
		return p
	}
	panic("invalid connection mode set for grpc-runtime")
}

type target struct {
	addressOrPod string
	node         string
}

func getGadgetPods(ctx context.Context, config *rest.Config, nodes []string, gadgetNamespace string) ([]target, error) {
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("setting up trace client: %w", err)
	}

	opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
	pods, err := client.CoreV1().Pods(gadgetNamespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("getting pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no gadget pods found in namespace %q. Is Inspektor Gadget deployed?", gadgetNamespace)
	}

	if len(nodes) == 0 {
		res := make([]target, 0, len(pods.Items))

		for _, pod := range pods.Items {
			res = append(res, target{addressOrPod: pod.Name, node: pod.Spec.NodeName})
		}

		return res, nil
	}

	res := make([]target, 0, len(nodes))
nodesLoop:
	for _, node := range nodes {
		for _, pod := range pods.Items {
			if node == pod.Spec.NodeName {
				res = append(res, target{addressOrPod: pod.Name, node: node})
				continue nodesLoop
			}
		}
		return nil, fmt.Errorf("node %q does not have a gadget pod", node)
	}

	return res, nil
}

// getTargets returns targets depending on the params given and the environment. The returned
// bool is true, if the user explicitly selected the nodes using params.
func (r *Runtime) getTargets(ctx context.Context, params *params.Params) ([]target, error) {
	switch r.connectionMode {
	case ConnectionModeKubernetesProxy:
		// Get nodes to run on
		nodes := params.Get(ParamNode).AsStringSlice()
		gadgetNamespace := r.globalParams.Get(ParamGadgetNamespace).AsString()
		pods, err := getGadgetPods(ctx, r.restConfig, nodes, gadgetNamespace)
		if err != nil {
			return nil, fmt.Errorf("get gadget pods: %w", err)
		}
		if len(pods) == 0 {
			return nil, fmt.Errorf("get gadget pods: Inspektor Gadget is not running on the requested node(s): %v", nodes)
		}
		return pods, nil
	case ConnectionModeDirect:
		inTargets := r.globalParams.Get(ParamRemoteAddress).AsStringSlice()
		targets := make([]target, 0)
		for _, t := range inTargets {
			purl, err := url.Parse(t)
			if err != nil {
				return nil, fmt.Errorf("invalid remote address %q: %w", t, err)
			}
			tg := target{
				addressOrPod: purl.Host,
				node:         purl.Hostname(),
			}
			if purl.Scheme == "unix" {
				// use the whole url in case of a unix socket and "local" as node
				tg.addressOrPod = t
				tg.node = "local"
			}
			targets = append(targets, tg)
		}
		return targets, nil
	}
	return nil, fmt.Errorf("unsupported connection mode")
}

func (r *Runtime) getConnToRandomTarget(ctx context.Context, runtimeParams *params.Params) (*grpc.ClientConn, error) {
	targets, err := r.getTargets(ctx, runtimeParams)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}
	target := targets[0]
	log.Debugf("using target %q (%q)", target.addressOrPod, target.node)

	timeout := time.Second * time.Duration(r.globalParams.Get(ParamConnectionTimeout).AsUint16())
	conn, err := r.dialContext(ctx, target, timeout)
	if err != nil {
		return nil, fmt.Errorf("dialing %q (%q): %w", target.addressOrPod, target.node, err)
	}
	return conn, nil
}

func (r *Runtime) getConnFromTarget(ctx context.Context, runtimeParams *params.Params, target target) (*grpc.ClientConn, error) {
	log.Debugf("using target %q (%q)", target.addressOrPod, target.node)

	timeout := time.Second * time.Duration(r.globalParams.Get(ParamConnectionTimeout).AsUint16())
	conn, err := r.dialContext(ctx, target, timeout)
	if err != nil {
		return nil, fmt.Errorf("dialing %q (%q): %w", target.addressOrPod, target.node, err)
	}
	return conn, nil
}

func (r *Runtime) dialContext(dialCtx context.Context, target target, timeout time.Duration) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		//nolint:staticcheck
		grpc.WithBlock(),
		//nolint:staticcheck
		grpc.WithReturnConnectionError(),
	}

	tlsKey := r.globalParams.Get(ParamTLSKey).String()
	tlsCert := r.globalParams.Get(ParamTLSCert).String()
	tlsCA := r.globalParams.Get(ParamTLSServerCA).String()

	tlsOptionsSet := 0
	for _, tlsOption := range []string{tlsKey, tlsCert, tlsCA} {
		if len(tlsOption) != 0 {
			tlsOptionsSet++
		}
	}

	if tlsOptionsSet > 1 && tlsOptionsSet < 3 {
		return nil, fmt.Errorf(`
missing at least one the TLS related options:
	* %s: %q
	* %s: %q
	* %s: %q
All these options should be set at the same time to enable TLS connection`,
			ParamTLSKey, tlsKey,
			ParamTLSCert, tlsCert,
			ParamTLSServerCA, tlsCA)
	}

	if tlsOptionsSet == 3 {
		cert, err := gadgettls.LoadTLSCert(tlsCert, tlsKey)
		if err != nil {
			return nil, fmt.Errorf("creating TLS certificate: %w", err)
		}

		ca, err := gadgettls.LoadTLSCA(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("creating TLS certificate authority: %w", err)
		}

		purl, err := url.Parse(target.addressOrPod)
		if err != nil {
			return nil, fmt.Errorf("parsing address %v: %w", target.addressOrPod, err)
		}

		tlsConfig := &tls.Config{
			ServerName:   purl.Hostname(),
			Certificates: []tls.Certificate{cert},
			RootCAs:      ca,
		}

		if serverName := r.globalParams.Get(ParamTLSServerName).String(); serverName != "" {
			tlsConfig.ServerName = serverName
		}

		if tlsConfig.ServerName == "" {
			return nil, fmt.Errorf("invalid hostname, use %s to override", ParamTLSServerName)
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// If we're in Kubernetes connection mode, we need a custom dialer
	if r.connectionMode == ConnectionModeKubernetesProxy {
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			port := r.globalParams.Get(ParamGadgetServiceTCPPort).AsUint16()
			gadgetNamespace := r.globalParams.Get(ParamGadgetNamespace).AsString()
			return NewK8SPortFwdConn(ctx, r.restConfig, gadgetNamespace, target, port, timeout)
		}))
	} else {
		newCtx, cancel := context.WithTimeout(dialCtx, timeout)
		defer cancel()
		dialCtx = newCtx
	}

	//nolint:staticcheck
	conn, err := grpc.DialContext(dialCtx, "passthrough:///"+target.addressOrPod, opts...)
	if err != nil {
		return nil, fmt.Errorf("dialing %q (%q): %w", target.addressOrPod, target.node, err)
	}
	return conn, nil
}

func (r *Runtime) SetDefaultValue(key params.ValueHint, value string) {
	r.defaultValues[strings.ToLower(string(key))] = value
}

func (r *Runtime) GetDefaultValue(key params.ValueHint) (string, bool) {
	val, ok := r.defaultValues[strings.ToLower(string(key))]
	return val, ok
}
