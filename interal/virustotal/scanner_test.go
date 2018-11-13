package virustotal

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/worlvlhole/maladapt/internal/digests"
	"github.com/worlvlhole/maladapt/pkg/ipc"
	"github.com/worlvlhole/maladapt/pkg/plugin"
)

var Hashes = []string{
	"99017f6eebbac24f351415dd410d522d",
	"1234",
	"abcdef",
	"64",
}

type scanResult struct {
	result *plugins.Result
	err    bool
}

var ResultsTable = map[string]scanResult{
	"99017f6eebbac24f351415dd410d522d": {
		result: &plugins.Result{
			Details: plugins.VirusScanResult{Positives: 5, TotalScans: 5},
		},
	},
	"1234": {
		result: &plugins.Result{
			Details: plugins.VirusScanResult{Positives: 0, TotalScans: 0},
		},
	},
	"abcdef": {
		err: true,
	},
	"63": {
		result: &plugins.Result{
			Details: plugins.VirusScanResult{Positives: 1, TotalScans: 7},
		},
	},
	"64": {
		result: &plugins.Result{
			Details: plugins.VirusScanResult{Positives: 1, TotalScans: 1},
		},
	},
}

func TestResults(t *testing.T) {

	file, err := os.Open("testdata/virustotal.json")
	if err != nil {
		t.Fatal(err)
	}

	api := NewTestAPI(file)
	pollInterval := time.Millisecond * 10
	reqsPerMin := len(ResultsTable) * 10
	scanner := NewScanner(api, pollInterval, uint(reqsPerMin))

	for _, hash := range Hashes {
		digest, err := hex.DecodeString(hash)
		if err != nil {
			t.Fatalf("unable to digest %q", hash)
		}
		scan := ipc.Scan{
			Digests: []digests.Digest{
				{Algorithm: "md5", Hash: digest},
			},
		}

		actual, ok := ResultsTable[hash]
		if !ok {
			t.Fatalf("No result found for %s", hash)
		}

		var ch <-chan int
		// simulate transition from pending to available
		if response, err := api.FileReport(hash); err == nil && response.ResponseCode == reportPending {
			ch = api.transitionToAvailable(hash, pollInterval+3)
		}

		if ch != nil {
			<-ch
		}

		result, err := scanner.Scan(scan)
		if actual.err {
			if err == nil {
				t.Fatal("Expected an error processing message")
			}
		} else {
			if actual.result.Details.(plugins.VirusScanResult).Positives != result.Details.(plugins.VirusScanResult).Positives {
				t.Fatalf("Want Positives: %v, Got : %v",
					actual.result.Details.(plugins.VirusScanResult).Positives,
					result.Details.(plugins.VirusScanResult).Positives,
				)
			}
			if actual.result.Details.(plugins.VirusScanResult).TotalScans != result.Details.(plugins.VirusScanResult).TotalScans {
				t.Fatalf("Want  Totalscans: %v, Got : %v", actual.result.Details.(plugins.VirusScanResult).TotalScans,
					result.Details.(plugins.VirusScanResult).TotalScans,
				)
			}
		}
	}
}
