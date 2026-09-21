// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

// DefaultSDConfig is the default AWS SD configuration.
var DefaultSDConfig = SDConfig{
	Port:               80,
	RefreshInterval:    model.Duration(60 * time.Second),
	HTTPClientConfig:   config.DefaultHTTPClientConfig,
	RequestConcurrency: 10,
}

func init() {
	discovery.RegisterConfig(&SDConfig{})
}

// Role is role of the service in AWS.
type Role string

// The valid options for Role.
const (
	RoleEC2         Role = "ec2"
	RoleECS         Role = "ecs"
	RoleElasticache Role = "elasticache"
	RoleLightsail   Role = "lightsail"
	RoleMSK         Role = "msk"
	RoleRDS         Role = "rds"
)

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *Role) UnmarshalYAML(unmarshal func(any) error) error {
	if err := unmarshal((*string)(c)); err != nil {
		return err
	}
	switch *c {
	case RoleEC2, RoleECS, RoleElasticache, RoleLightsail, RoleMSK, RoleRDS:
		return nil
	default:
		return fmt.Errorf("unknown AWS SD role %q", *c)
	}
}

func (c Role) String() string {
	return string(c)
}

// Filter is the configuration for filtering AWS resources.
type Filter struct {
	Name   string   `yaml:"name"`
	Values []string `yaml:"values"`
}

// awsDiscovery is an interface that defines the method for refreshing AWS targets.
// Each AWS service discovery implementation (e.g., EC2, ECS, RDS) will implement this interface
// to provide its own logic for fetching and returning target groups.
type awsDiscovery interface {
	refresh(context.Context) ([]*targetgroup.Group, error)
}

// SDConfig is the configuration for AWS service discovery.
type SDConfig struct {
	Role             Role                    `yaml:"role"`
	Region           string                  `yaml:"region,omitempty"`
	Endpoint         string                  `yaml:"endpoint,omitempty"`
	AccessKey        string                  `yaml:"access_key,omitempty"`
	SecretKey        config.Secret           `yaml:"secret_key,omitempty"`
	Profile          string                  `yaml:"profile,omitempty"`
	RoleARN          string                  `yaml:"role_arn,omitempty"`
	ExternalID       string                  `yaml:"external_id,omitempty"`
	RefreshInterval  model.Duration          `yaml:"refresh_interval,omitempty"`
	Port             int                     `yaml:"port,omitempty"`
	HTTPClientConfig config.HTTPClientConfig `yaml:",inline"`
	// RequestConcurrency controls the maximum number of concurrent AWS API requests.
	RequestConcurrency int `yaml:"request_concurrency,omitempty"`

	// ec2, rds specific
	Filters []*Filter `yaml:"filters,omitempty"`

	// ecs, msk specific
	Clusters []string `yaml:"clusters,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for SDConfig.
func (c *SDConfig) UnmarshalYAML(unmarshal func(any) error) error {
	*c = DefaultSDConfig
	// Alias to avoid recursion
	type plain SDConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	if c.RequestConcurrency <= 0 {
		return fmt.Errorf("aws_sd: request_concurrency must be positive, got %d", c.RequestConcurrency)
	}

	for _, f := range c.Filters {
		if len(f.Values) == 0 {
			return errors.New("Filter values cannot be empty")
		}
	}

	return c.HTTPClientConfig.Validate()
}

// Name returns the name of the AWS Config.
func (*SDConfig) Name() string { return "aws" }

// NewDiscovererMetrics implements discovery.Config.
func (*SDConfig) NewDiscovererMetrics(_ prometheus.Registerer, rmi discovery.RefreshMetricsInstantiator) discovery.DiscovererMetrics {
	return &awsMetrics{refreshMetrics: rmi}
}

// NewDiscoverer returns a Discoverer for the AWS Config.
func (c *SDConfig) NewDiscoverer(opts discovery.DiscovererOptions) (discovery.Discoverer, error) {
	return NewDiscovery(c, opts)
}

// Discovery implements the Discoverer interface.
type Discovery struct {
	*refresh.Discovery
	logger *slog.Logger
	cfg    *SDConfig
	region string

	awsDiscovery
}

// NewDiscovery returns a new Discovery which periodically refreshes its targets.
func NewDiscovery(conf *SDConfig, opts discovery.DiscovererOptions) (*Discovery, error) {
	m, ok := opts.Metrics.(*awsMetrics)
	if !ok {
		return nil, errors.New("invalid discovery metrics type for AWS SD")
	}

	if opts.Logger == nil {
		opts.Logger = promslog.NewNopLogger()
	}
	d := &Discovery{
		logger: opts.Logger,
		cfg:    conf,
	}
	ctx := context.Background()
	var err error
	awsCfg, err := d.newAWSCfg(ctx)
	if err != nil {
		return nil, err
	}
	d.Discovery = refresh.NewDiscovery(
		refresh.Options{
			Logger:              opts.Logger,
			Mech:                "aws",
			SetName:             opts.SetName,
			Interval:            time.Duration(d.cfg.RefreshInterval),
			RefreshF:            d.refresh,
			MetricsInstantiator: m.refreshMetrics,
		},
	)

	switch d.cfg.Role {
	case RoleEC2:
		d.awsDiscovery, err = newEC2Discovery(ctx, awsCfg, d)
		if err != nil {
			d.logger.Error("Failed to create EC2 discovery", "error", err)
			return nil, err
		}
	case RoleECS:
		d.awsDiscovery, err = newECSDiscovery(ctx, awsCfg, d)
		if err != nil {
			d.logger.Error("Failed to create ECS discovery", "error", err)
			return nil, err
		}
	case RoleElasticache:
		d.awsDiscovery, err = newElasticacheDiscovery(ctx, awsCfg, d)
		if err != nil {
			d.logger.Error("Failed to create Elasticache discovery", "error", err)
			return nil, err
		}
	case RoleLightsail:
		d.awsDiscovery, err = newLightsailDiscovery(ctx, awsCfg, d)
		if err != nil {
			d.logger.Error("Failed to create Lightsail discovery", "error", err)
			return nil, err
		}
	case RoleMSK:
		d.awsDiscovery, err = newMSKDiscovery(ctx, awsCfg, d)
		if err != nil {
			d.logger.Error("Failed to create MSK discovery", "error", err)
			return nil, err
		}
	case RoleRDS:
		d.awsDiscovery, err = newRDSDiscovery(ctx, awsCfg, d)
		if err != nil {
			d.logger.Error("Failed to create RDS discovery", "error", err)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown AWS SD role %q", d.cfg.Role)
	}

	return d, nil
}

// SetDirectory joins any relative file paths with dir.
func (c *SDConfig) SetDirectory(dir string) {
	c.HTTPClientConfig.SetDirectory(dir)
}

// loadRegion finds the region in order: configured region -> AWS config/env vars -> IMDS.
// Region resolution is intentionally deferred to SD init so config-only operations
// (e.g. `promtool check config`) stay free of network I/O. See the UnmarshalYAML
// docstrings in this package.
func loadRegion(ctx context.Context, specifiedRegion string) (region string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("could not determine AWS region: %w", err)
		}
	}()

	if specifiedRegion != "" {
		return specifiedRegion, nil
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	if cfg.Region != "" {
		return cfg.Region, nil
	}

	// Fallback (may fail in non-AWS environments)
	imdsClient := imds.NewFromConfig(cfg)
	imdsRegion, err := imdsClient.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get region from IMDS: %w", err)
	}

	if imdsRegion.Region == "" {
		return "", errors.New("region not found in AWS config or IMDS")
	}

	return imdsRegion.Region, nil
}

func (d *Discovery) newAWSCfg(ctx context.Context) (aws.Config, error) {

	// Build the HTTP client from the provided HTTPClientConfig.
	httpClient, err := config.NewClientFromConfig(d.cfg.HTTPClientConfig, "aws_sd")
	if err != nil {
		return aws.Config{}, err
	}

	d.region, err = loadRegion(ctx, d.cfg.Region)
	if err != nil {
		return aws.Config{}, err
	}

	// Build the AWS config with the resolved region.
	configOptions := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithRegion(d.region),
		awsConfig.WithHTTPClient(httpClient),
	}

	// Only set static credentials if both access key and secret key are provided.
	// Otherwise, let the AWS SDK use its default credential chain (environment variables, IAM role, etc.).
	if d.cfg.AccessKey != "" && d.cfg.SecretKey != "" {
		credProvider := credentials.NewStaticCredentialsProvider(d.cfg.AccessKey, string(d.cfg.SecretKey), "")
		configOptions = append(configOptions, awsConfig.WithCredentialsProvider(credProvider))
	}

	// Set the profile if provided.
	if d.cfg.Profile != "" {
		configOptions = append(configOptions, awsConfig.WithSharedConfigProfile(d.cfg.Profile))
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx, configOptions...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("could not create aws config: %w", err)
	}

	// If the role ARN is set, assume the role to get credentials and set the credentials provider in the config.
	if d.cfg.RoleARN != "" {
		assumeProvider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), d.cfg.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if d.cfg.ExternalID != "" {
				o.ExternalID = aws.String(d.cfg.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(assumeProvider)
	}

	return cfg, nil
}

func (d *Discovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	return d.awsDiscovery.refresh(ctx)
}
