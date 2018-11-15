package main

import (
	"strings"
	"log/syslog"
	"net/http"

	"github.com/spf13/viper"
	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/hashicorp/go-plugin"
	
	"github.com/worlvlhole/maladapt/pkg/plugin"
	
	"github.com/worlvlhole/virustotal-plugin/interal/virustotal"
)


const (
	envPrefix     = "MAL"
)

func main() {
	//Setup Logger
	log.SetFormatter(&log.JSONFormatter{})
	hook, err := lSyslog.NewSyslogHook("", "", syslog.LOG_DEBUG, "virustotal")
	if err != nil {
		log.Error("could not setup syslog logger")
	} else {
		log.AddHook(hook)
	}

	log.Info("Starting virustotal plugin")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	vtCfg := virustotal.NewConfigurationFromViper(viper.GetViper())
	if err := vtCfg.Validate(); err != nil {
		log.Fatal(err)
	}

	httpClient := http.DefaultClient
	httpClient.Timeout = vtCfg.Timeout
	vtAPI := virustotal.NewRestAPI(vtCfg.URL, vtCfg.APIKey, httpClient)

	scanner := virustotal.NewScanner(
		vtAPI,
		vtCfg.PollInterval,
		vtCfg.RequestsPerMinute,
	)

	pluginMap := map[string]plugin.Plugin{
		"av_scanner": &plugins.AVScannerGRPCPlugin{Impl: scanner},
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: pluginMap,
		GRPCServer: plugin.DefaultGRPCServer,
	})

}
