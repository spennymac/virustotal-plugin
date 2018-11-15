package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/worlvlhole/maladapt/internal/token/policy"

	"github.com/worlvlhole/maladapt/pkg/digests"
)

const (
	//VirusScan result type
	VirusScan string = "VirusScan"
)

//VirusScanResult represents the output of scanning
//a file by a virus scanner
type VirusScanResult struct {
	Positives  int         `json:"positives" bson:"positives"`       //number of infected scans
	TotalScans int         `json:"totalScans" bson:"totalScans"`     //total number of scans performed
	Context    interface{} `json:"context" bson:"context,omitempty"` //additional virus scanner specific details
}

//Result represents an individual plugins
//results for scanning a file
type Result struct {
	Time    time.Time   `json:"time" bson:"time"`       //time the scan began
	Type    string      `json:"type"  bson:"type"`      //type of scan perfomed
	Details interface{} `json:"details" bson:"details"` //Type specific scan details
}

//Scan represents a single scan of a file
type Scan struct {
	ID             uuid.UUID           `bson:"_id"`            //unique id of scan
	File           uuid.UUID           `bson:"file"`           //id of file being scanned
	Time           time.Time           `bson:"time"`           //time the scan began
	TotalScans     int                 `bson:"totalScans"`     //number of scan performed
	ScansCompleted int                 `bson:"scansCompleted"` //number of scans completed
	Results        map[string][]Result `bson:"results"`        //plugin results
	Permalink      string              `bson:"permalink"`      //permalink for user
}

//File contains meta data about an uploaded file
type File struct {
	ID       uuid.UUID        `bson:"_id"`      //unique id
	Filename string           `bson:"filename"` //name of file
	Location string           `bson:"location"` //location in quarantine
	Digests  []digests.Digest `bson:"digests"`  //computed digests of contents
	Scans    []uuid.UUID      `bson:"scans"`    //scans performed on the file
}

//Plugin represents an entity that
// is scanning files
type Plugin struct {
	ID         uuid.UUID `bson:"_id"`        //unique id
	Name       string    `bson:"name"`       //name of plugin
	LastActive time.Time `bson:"lastActive"` //time last heard from
}

//APIToken represents a token used for authorization
type APIToken struct {
	ID        uuid.UUID                       `bson:"_id"`       //unique id
	Token     []byte                          `bson:"token"`     //token
	Policies  map[policy.RuleType]policy.Rule `bson:"rules"`     //rules
	CreatedAt time.Time                       `bson:"createdAt"` //createdAt
}
