package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"

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

//PluginMap defines the types of plugins supported
var PluginMap = map[string]plugin.Plugin{
	"av_scanner": &AVScannerGRPCPlugin{},
}

// AVScannerGRPCClient is an implementation of Plugin that talks over RPC.
type AVScannerGRPCClient struct{ client proto.AVScannerPluginClient }

//Scan impl plugin interface
func (a *AVScannerGRPCClient) Scan(scan ipc.Scan) (Result, error) {

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
		Digests:  digests,
	}

	logger.WithField("request", req).Info("Sending scan request")
	resp, err := a.client.Scan(context.Background(), &req)

	if err != nil {
		return Result{}, err
	}

	time, err := ptypes.Timestamp(resp.Time)
	if err != nil {
		return Result{}, err
	}

	var context map[string]interface{}
	err = json.Unmarshal(resp.Result.Context, &context)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Time: time,
		Type: resp.Type,
		Details: VirusScanResult{
			Positives:  int(resp.Result.Positives),
			TotalScans: int(resp.Result.TotalScans),
			Context:    context,
		},
	}, nil
}

// AVScannerGRPCServer is the gRPC server that GRPCClient talks to.
type AVScannerGRPCServer struct {
	// This is the real implementation
	Impl Plugin
}

//Scan impl of plugin interface
func (a *AVScannerGRPCServer) Scan(ctx context.Context,
	req *proto.ScanRequest) (*proto.AVScanResponse, error) {

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
		ID:       id,
		Filename: req.Filename,
		Location: req.Location,
		Digests:  digests,
	}

	result, err := a.Impl.Scan(scan)
	if err != nil {
		return nil, err
	}

	if result.Type != VirusScan {
		return nil, errors.New("invalid result type")
	}

	vsr, ok := result.Details.(VirusScanResult)
	if !ok {
		return nil, errors.New("invalid result type")
	}

	time, err := ptypes.TimestampProto(result.Time)
	if err != nil {
		return nil, err
	}

	context, err := json.Marshal(vsr.Context)
	if err != nil {
		return nil, err
	}

	return &proto.AVScanResponse{
		Time: time,
		Type: result.Type,
		Result: &proto.AVScanResponse_AVScanResult{
			Positives:  int32(vsr.Positives),
			TotalScans: int32(vsr.TotalScans),
			Context:    context,
		},
	}, err
}

// AVScannerGRPCPlugin is the implementation of plugin.GRPCPlugin so we can serve/consume this.
type AVScannerGRPCPlugin struct {
	// GRPCPlugin must still implement the Plugin interface
	plugin.Plugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl Plugin
}

//GRPCServer implements server
func (p *AVScannerGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterAVScannerPluginServer(s, &AVScannerGRPCServer{Impl: p.Impl})
	return nil
}

//GRPCClient implements client
func (p *AVScannerGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &AVScannerGRPCClient{client: proto.NewAVScannerPluginClient(c)}, nil
}
