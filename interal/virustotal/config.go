package virustotal

import (
	"errors"
	"time"

	"github.com/spf13/viper"
)

//Configuration defines the items needed to launch the virustotal plugin
type Configuration struct {
	URL               string
	APIKey            string
	Timeout           time.Duration
	PollInterval      time.Duration
	RequestsPerMinute uint
}

// NewConfigurationFromViper creates a Configuration from the values
// provided by the viper instance
func NewConfigurationFromViper(cfg *viper.Viper) Configuration {
	return NewConfiguration(
		cfg.GetString("virustotal.url"),
		cfg.GetString("virustotal.api_key"),
		cfg.GetDuration("virustotal.timeout"),
		cfg.GetDuration("virustotal.poll_interval"),
		cfg.GetInt("virustotal.requests_per_minute"),
	)
}

// Validate implements the Validate interface.
func (c *Configuration) Validate() error {
	if c.URL == "" {
		return errors.New("virustotal URL not set")
	}

	if c.APIKey == "" {
		return errors.New("virustotal APIKey not set")
	}

	if c.Timeout == time.Second*0 {
		return errors.New("virustotal Timeout not set")
	}

	if c.PollInterval == time.Second*0 {
		return errors.New("virustotal PollInterval not set")
	}

	if c.RequestsPerMinute == 0 {
		return errors.New("virustotal RequestsPerMinute not set")
	}

	return nil
}

// NewConfiguration creates a new Configuration from the provided values
func NewConfiguration(url, apiKey string,
	timeout time.Duration,
	pollInterval time.Duration,
	requestsPerMinute int,
) Configuration {
	return Configuration{
		URL:               url,
		APIKey:            apiKey,
		Timeout:           timeout,
		PollInterval:      pollInterval,
		RequestsPerMinute: uint(requestsPerMinute),
	}
}
