package main

import (
	"net/http"

	"github.com/spf13/viper"

	"github.com/worlvlhole/virustotal-plugin/interal/virustotal"
	"github.com/worlvlhole/maladapt/pkg/ipc"
	"github.com/worlvlhole/maladapt/pkg/plugin"
)

type vt struct {
	scanner *virustotal.Scanner
}

func newVT(cfg *viper.Viper) (*vt, error) {
	vtCfg := virustotal.NewConfigurationFromViper(cfg)
	if err := vtCfg.Validate(); err != nil {
		return nil, err
	}

	httpClient := http.DefaultClient
	httpClient.Timeout = vtCfg.Timeout
	vtAPI := virustotal.NewRestAPI(vtCfg.URL, vtCfg.APIKey, httpClient)

	scanner := virustotal.NewScanner(
		vtAPI,
		vtCfg.PollInterval,
		vtCfg.RequestsPerMinute,
	)

	return &vt{scanner: scanner}, nil
}

func (v vt) Scan(scan ipc.Scan) (plugins.Result, error) {
	return v.scanner.Scan(scan)
}

//NewPlugin creates the plugin to be used by the plugin module
func NewPlugin() (plugins.Plugin, error) {
	plugin, err := newVT(viper.GetViper())

	if err != nil {
		return nil, err
	}

	return plugin, nil
}
