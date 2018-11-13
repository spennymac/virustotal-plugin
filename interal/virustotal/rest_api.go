package virustotal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RestAPI communicates with virustotal REST API
type RestAPI struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

//NewRestAPI constructs a new RestAPI from the given params
func NewRestAPI(url, apiKey string, client *http.Client) *RestAPI {
	return &RestAPI{baseURL: url, apiKey: apiKey, client: client}
}

//FileReport gets reports from virustotal.Resources are file digests to query virustotal for
func (r RestAPI) FileReport(resource ...string) (*ReportResponse, error) {
	url := fmt.Sprintf("%s/file/report", r.baseURL)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	params := req.URL.Query()
	params.Add("apikey", r.apiKey)
	params.Add("resource", strings.Join(resource, ","))
	req.URL.RawQuery = params.Encode()

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal returned %s", resp.Status)
	}

	res := ReportResponse{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}
