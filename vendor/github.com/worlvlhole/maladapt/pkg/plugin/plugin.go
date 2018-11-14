package plugins

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/google/uuid"
	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/worlvlhole/maladapt/pkg/digests"
	"github.com/worlvlhole/maladapt/pkg/ipc"
	"github.com/worlvlhole/maladapt/pkg/plugin/proto"
)

// Plugin interface to be implemented by all plugin modules
type Plugin interface {
	Scan(scan ipc.Scan) (Result, error)
}

const (
	//VirusScan result type
	VirusScan string = "VirusScan"
)

//VirusScanResult represents the output of scanning
//a file by a virus scanner
type VirusScanResult struct {
	Positives  int         `json:"positives"`         //number of infected scans
	TotalScans int         `json:"totalScans"`        //total number of scans performed
	Context    interface{} `json:"context,omitempty"` //additional virus scanner specific details
}

//Result represents an individual plugins
//results for scanning a file
type Result struct {
	Time    time.Time   `json:"time"`    //time the scan began
	Type    string      `json:"type"`    //type of scan perfomed
	Details interface{} `json:"details"` //Type specific scan details
}

//HandshakeConfig to be used for plugin communication initialization
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct{ client proto.PluginClient }

//Scan impl plugin interface
func (m *GRPCClient) Scan(scan ipc.Scan) (Result, error) {
	
	logger := log.WithFields(log.Fields{"func": "Scan"})

	digests := make([]*proto.Digest, len(scan.Digests))
	for i, d := range scan.Digests {
		digest := new(proto.Digest)
		digest.Algorithm = d.Algorithm
		digest.Hash = d.Hash

		digests[i] = digest
	}

	req := proto.ScanRequest{
		Id:       scan.ID.String(),
		Filename: scan.Filename,
		Location: scan.Location,
		Digests:   digests,
	}

	logger.WithField("request", req).Info("Sending scan request")
	resp, err := m.client.Scan(context.Background(), &req)

	if err != nil {
		return Result{}, err
	}

	time, err := ptypes.Timestamp(resp.Time)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Time:    time,
		Type:    resp.Type,
		Details: nil,
	}, nil
}

// GRPCServer is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl Plugin
}

//Scan impl of plugin interface
func (m *GRPCServer) Scan(ctx context.Context,
	req *proto.ScanRequest) (*proto.ScanResponse, error) {

	id, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, err
	}

	digests := make([]digests.Digest, len(req.Digests))
	for i, d := range req.Digests {
		digests[i].Algorithm = d.Algorithm
		digests[i].Hash = d.Hash
	}

	scan := ipc.Scan{
		ID: id,
		Filename: req.Filename,
		Location: req.Location,
		Digests: digests,
	}

	result, err := m.Impl.Scan(scan)
	if err != nil {
		return nil, err
	}

	time, err := ptypes.TimestampProto(result.Time)
	if err != nil {
		return nil, err
	}

	return &proto.ScanResponse{
		Time:    time,
		Type:    result.Type,
		Details: nil,
	}, err
}

// ScannerGRPCPlugin is the implementation of plugin.GRPCPlugin so we can serve/consume this.
type ScannerGRPCPlugin struct {
	// GRPCPlugin must still implement the Plugin interface
	plugin.Plugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl Plugin
}

//GRPCServer implements server
func (p *ScannerGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterPluginServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

//GRPCClient implements client
func (p *ScannerGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewPluginClient(c)}, nil
}
