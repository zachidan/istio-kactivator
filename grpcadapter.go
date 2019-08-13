// nolint:lll
// Generates the kactivator adapter's resource yaml. It contains the adapter's configuration, name, supported template
// names (authorization in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/kactivator/config/config.proto -x "-s=false -n kactivator -t authorization"

package kactivator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
        "strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"istio.io/api/mixer/adapter/model/v1beta1"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/pkg/log"

	"github.com/knative/pkg/websocket"
	"github.com/knative/pkg/logging/logkey"
	"github.com/knative/serving/pkg/logging"
	"go.uber.org/zap"
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run(shutdown chan error)
	}

	// GrpcAdapter supports authorization template.
	GrpcAdapter struct {
		listener   net.Listener
		server    *grpc.Server
		statSink  *websocket.ManagedConnection
		podName    string
	}
)

// Stat defines a single measurement at a point in time
type Stat struct {
	// The time the data point was received by autoscaler.
	Time *time.Time

	// The unique identity of this pod.  Used to count how many pods
	// are contributing to the metrics.
	PodName string

	// Average number of requests currently being handled by this pod.
	AverageConcurrentRequests float64

	// Part of AverageConcurrentRequests, for requests going through a proxy.
	AverageProxiedConcurrentRequests float64

	// Number of requests received since last Stat (approximately QPS).
	RequestCount int32

	// Part of RequestCount, for requests going through a proxy.
	ProxiedRequestCount int32
}

// StatMessage wraps a Stat with identifying information so it can be routed
// to the correct receiver.
type StatMessage struct {
	Key  string
	Stat Stat
}

var _ authorization.HandleAuthorizationServiceServer = &GrpcAdapter{}

// Send StatMessage to the Knative AutoScaler
func (s *GrpcAdapter) sendStatMessage(r *authorization.HandleAuthorizationRequest) {
	namespace := r.Instance.Action.Namespace
        service := r.Instance.Action.Service
        sm := StatMessage{Key: fmt.Sprintf("%s/%s", namespace, strings.TrimSuffix(service, "-priv"))}
        sm.Stat.PodName = s.podName
        sm.Stat.AverageConcurrentRequests = 1.0
        sm.Stat.RequestCount = 1
        s.statSink.Send(&sm)
}

// HandleAuthorization request
func (s *GrpcAdapter) HandleAuthorization(ctx context.Context, r *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	log.Debugf("received request %v\n", *r)
	s.sendStatMessage(r)
	return &v1beta1.CheckResult{ValidDuration: 4 * time.Minute}, nil
}

// Addr returns the listening address of the server
func (s *GrpcAdapter) Addr() string {
	return s.listener.Addr().String()
}

// Run starts the server run
func (s *GrpcAdapter) Run(shutdown chan error) {
	shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *GrpcAdapter) Close() error {
	if s.server != nil {
		s.server.GracefulStop()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	return nil
}

func getServerTLSOption(credential, privateKey, caCertificate string) (grpc.ServerOption, error) {
	certificate, err := tls.LoadX509KeyPair(
		credential,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load key cert pair")
	}
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile(caCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to read client ca cert: %s", err)
	}

	ok := certPool.AppendCertsFromPEM(bs)
	if !ok {
		return nil, fmt.Errorf("failed to append client certs")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}

// NewGrpcAdapter creates a new IBP adapter that listens at provided port.
func NewGrpcAdapter(addr string) (Server, error) {
	if addr == "" {
		addr = "0"
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", addr))
	if err != nil {
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}
	s := &GrpcAdapter{
		listener: listener,
	}
	fmt.Printf("listening on \"%v\"\n", s.Addr())

	// Open a websocket to communicate with the Knative AutoScaler
	autoscalerEndpoint := os.Getenv("AUTOSCALER_ENDPOINT")
        s.podName = os.Getenv("POD_NAME")
        createdLogger, _ := logging.NewLogger("", "")
        logger := createdLogger.With(zap.String(logkey.ControllerType, "activator"))
        s.statSink = websocket.NewDurableSendingConnection(autoscalerEndpoint, logger)

	credential := os.Getenv("GRPC_ADAPTER_CREDENTIAL")
	privateKey := os.Getenv("GRPC_ADAPTER_PRIVATE_KEY")
	certificate := os.Getenv("GRPC_ADAPTER_CERTIFICATE")
	if credential != "" {
		so, err := getServerTLSOption(credential, privateKey, certificate)
		if err != nil {
			return nil, err
		}
		s.server = grpc.NewServer(so)
	} else {
		s.server = grpc.NewServer()
	}
	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)
	return s, nil
}
