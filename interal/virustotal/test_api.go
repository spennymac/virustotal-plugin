package virustotal

import (
	"encoding/json"
	"errors"
	"io"
	"time"
)

type testData map[string]*ReportResponse

//TestAPI is an in memory virustotal api service
type TestAPI struct {
	responses testData
}

//NewTestAPI uses the reader to create in memory responses.
//Contents of reader must be JSON
func NewTestAPI(r io.Reader) *TestAPI {
	dec := json.NewDecoder(r)

	var data testData
	for {
		if err := dec.Decode(&data); err == io.EOF {
			break
		}
	}

	return &TestAPI{responses: data}
}

//FileReport returns any responses loaded during construction
func (t TestAPI) FileReport(resource ...string) (*ReportResponse, error) {
	resp, ok := t.responses[resource[0]]

	if !ok {
		return nil, errors.New("response not found")
	}

	return resp, nil
}

func (t TestAPI) transitionToAvailable(resource string, at time.Duration) <-chan int {
	ch := make(chan int)
	go func() {
		time.Sleep(at)
		t.responses[resource].ResponseCode = reportPresent
		ch <- 1
		close(ch)
	}()
	return ch
}
