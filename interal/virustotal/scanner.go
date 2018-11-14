package virustotal

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/worlvlhole/maladapt/pkg/ipc"
	"github.com/worlvlhole/maladapt/pkg/plugin"
)

//ReportResponse virustotal FileReport api response
type ReportResponse struct {
	ResponseCode int                    `json:"response_code,omitempty"`
	VerboseMsg   string                 `json:"verbose_msg,omitempty"`
	Resource     string                 `json:"resource,omitempty"`
	ScanID       string                 `json:"scan_id,omitempty"`
	MD5          string                 `json:"md5,omitempty"`
	SHA1         string                 `json:"sha1,omitempty"`
	SHA256       string                 `json:"sha256,omitempty"`
	ScanDate     string                 `json:"scan_date,omitempty"`
	Positives    int                    `json:"positives,omitempty"`
	Total        int                    `json:"total,omitempty"`
	Scans        map[string]ScanResults `json:"scans,omitempty"`
	Permalink    string                 `json:"permalink,omitempty"`
}

//ScanResults virustotal scanner results
type ScanResults struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

const (
	reportNotFound int = 0
	reportPresent      = 1
	reportPending      = -2
)

//API represents the virustotal rest api
type API interface {
	FileReport(resource ...string) (*ReportResponse, error)
}

//Scanner is an interface to the virustotal api. It will use the provided api to
//communicate with virustotal.
type Scanner struct {
	api          API
	pollInterval time.Duration
	limiter      <-chan time.Time
}

//NewScanner constructs a new virustotal scanner object
func NewScanner(api API, pollInterval time.Duration, requestsPerMinute uint) *Scanner {
	reqInterval := time.Duration(60/requestsPerMinute) * time.Second
	limiter := time.Tick(reqInterval)
	return &Scanner{
		api:          api,
		pollInterval: pollInterval,
		limiter:      limiter,
	}
}

//Scan checks a digest from the provided scan message against the virustotal db
func (s Scanner) Scan(scan ipc.Scan) (plugins.Result, error) {
	<-s.limiter
	logger := log.WithFields(log.Fields{"func": "Scan"})

	logger.WithFields(log.Fields{
		"scan": scan,
	}).Warning("Fetching Report")

	if len(scan.Digests) <= 0 {
		logger.Error("no digests found")
		return plugins.Result{}, errors.New("no digests found")
	}

	report, err := s.api.FileReport(scan.Digests[0].String())
	if err != nil {
		return plugins.Result{}, err
	}

	switch report.ResponseCode {
	case reportPresent, reportNotFound:
		return generateResult(report), nil
	case reportPending:
		return s.pollReport(report.ScanID)
	default:
		logger.Error("unexpected file report response ", report.ResponseCode)
	}

	return plugins.Result{}, errors.New("no file present")
}

func (s Scanner) pollReport(resource string) (plugins.Result, error) {
	logger := log.WithFields(log.Fields{"func": "pollReport"})
	for {
		time.Sleep(s.pollInterval)
		rep, err := s.api.FileReport(resource)
		if err != nil {
			logger.Error(err)
			return plugins.Result{}, err
		}
		if rep.ResponseCode == reportPresent {
			return generateResult(rep), nil
		}
	}
}

func generateResult(report *ReportResponse) plugins.Result {
	logger := log.WithFields(log.Fields{"func": "generateResult"})
	if report.ResponseCode == reportNotFound {
		logger.Info("no report found")
		return plugins.Result{
			Time: time.Now(),
			Type: plugins.VirusScan,
			Details: plugins.VirusScanResult{
				Positives:  0,
				TotalScans: 0,
				Context:    report,
			},
		}
	}

	logger.Info("scan complete, Positives: ", report.Positives)
	return plugins.Result{
		Time: time.Now(),
		Type: plugins.VirusScan,
		Details: plugins.VirusScanResult{
			Positives:  report.Positives,
			TotalScans: report.Total,
			Context:    report},
	}
}
