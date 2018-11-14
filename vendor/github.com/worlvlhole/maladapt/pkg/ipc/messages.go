package ipc

import (
	"encoding/json"

	"github.com/google/uuid"

	"github.com/worlvlhole/maladapt/internal/model"
	"github.com/worlvlhole/maladapt/pkg/digests"
)

//Type message type
type Type = string

const (
	//MsgScan = Scan message type
	MsgScan Type = "Scan"
	//MsgScanReceived = ScanReceived message type
	MsgScanReceived = "ScanReceived"
	//MsgScanComplete = ScanComplete message type
	MsgScanComplete = "ScanComplete"
	//MsgPluginInfo = PluginInfo message type
	MsgPluginInfo = "PluginInfo"
)

//Scan message informing plugins to perform a scan
type Scan struct {
	ID       uuid.UUID        `json:"id"`
	Filename string           `json:"filename"`
	Location string           `json:"location"`
	Digests  []digests.Digest `json:"digests"`
}

//NewScan creates a Scan from the params
func NewScan(id uuid.UUID, filename string, digests []digests.Digest, location string) *Scan {
	return &Scan{
		ID:       id,
		Filename: filename,
		Digests:  digests,
		Location: location,
	}
}

//Compose creates a Message with correct type
func (s Scan) Compose() (*Message, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return &Message{MsgScan, body}, err
}

//ScanComplete message informing service that a plugin
//has completed a scan
type ScanComplete struct {
	Scanner string       `json:"scanner"`
	ScanID  uuid.UUID    `json:"scan_id"`
	Result  model.Result `json:"result"`
}

//NewScanComplete creates a ScanComplete from the params
func NewScanComplete(name string, scanID uuid.UUID, result model.Result) *ScanComplete {
	return &ScanComplete{
		Scanner: name,
		ScanID:  scanID,
		Result:  result,
	}
}

//Compose creates a Message with correct type
func (s ScanComplete) Compose() (*Message, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return &Message{MsgScanComplete, body}, err
}

//ScanReceived message informing service that a plugin
//has received a scan
type ScanReceived struct {
	Scanner string    `json:"scanner"`
	ScanID  uuid.UUID `json:"scan_id"`
}

//NewScanReceived creates a ScanReceived from the params
func NewScanReceived(name string, scanID uuid.UUID) *ScanReceived {
	return &ScanReceived{
		Scanner: name,
		ScanID:  scanID,
	}
}

//Compose creates a Message with correct type
func (s ScanReceived) Compose() (*Message, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return &Message{MsgScanReceived, body}, err
}

//PluginInfo message sent periodically to notify
//service about running plugins
type PluginInfo struct {
	Name string
}

//Compose creates a Message with correct type
func (p PluginInfo) Compose() (*Message, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Message{MsgPluginInfo, body}, err
}
