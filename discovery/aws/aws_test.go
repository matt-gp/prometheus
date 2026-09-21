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
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

func TestRoleUnmarshalYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected Role
		wantErr  bool
		// unmarshalErr is returned by the unmarshal func instead of input.
		unmarshalErr error
	}{
		{
			name:     "EC2Role",
			input:    "ec2",
			expected: RoleEC2,
			wantErr:  false,
		},
		{
			name:     "LightsailRole",
			input:    "lightsail",
			expected: RoleLightsail,
			wantErr:  false,
		},
		{
			name:     "ECSRole",
			input:    "ecs",
			expected: RoleECS,
			wantErr:  false,
		},
		{
			name:     "ElasticacheRole",
			input:    "elasticache",
			expected: RoleElasticache,
		},
		{
			name:     "MQRole",
			input:    "mq",
			expected: RoleMQ,
		},
		{
			name:     "MSKRole",
			input:    "msk",
			expected: RoleMSK,
		},
		{
			name:     "RDSRole",
			input:    "rds",
			expected: RoleRDS,
		},
		{
			name:     "InvalidRole",
			input:    "invalid",
			expected: "invalid",
			wantErr:  true,
		},
		{
			name:         "UnmarshalError",
			wantErr:      true,
			unmarshalErr: errors.New("boom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Role
			err := r.UnmarshalYAML(func(v any) error {
				ptr, ok := v.(*string)
				if !ok {
					return errors.New("not a string pointer")
				}
				*ptr = tt.input
				return nil
			})
			if tt.wantErr {
				require.Error(t, err, "expected error for input %q", tt.input)
			} else {
				require.NoError(t, err, "unexpected error for input %q", tt.input)
				require.Equal(t, tt.expected, r, "unexpected role for input %q", tt.input)
			}
		})
	}
}

func TestRoleString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		role     Role
		expected string
	}{
		{
			name:     "EC2",
			role:     RoleEC2,
			expected: "ec2",
		},
		{
			name:     "Lightsail",
			role:     RoleLightsail,
			expected: "lightsail",
		},
		{
			name:     "ECS",
			role:     RoleECS,
			expected: "ecs",
		},
		{
			name:     "Elasticache",
			role:     RoleElasticache,
			expected: "elasticache",
		},
		{
			name:     "MQ",
			role:     RoleMQ,
			expected: "mq",
		},
		{
			name:     "MSK",
			role:     RoleMSK,
			expected: "msk",
		},
		{
			name:     "RDS",
			role:     RoleRDS,
			expected: "rds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.role.String())
		})
	}
}

func TestSDConfigName(t *testing.T) {
	t.Parallel()
	cfg := &SDConfig{}
	require.Equal(t, "aws", cfg.Name())
}

func TestDefaultSDConfig(t *testing.T) {
	t.Parallel()
	require.Equal(t, Role(""), DefaultSDConfig.Role)
	require.Equal(t, model.Duration(60*time.Second), DefaultSDConfig.RefreshInterval)
	require.Equal(t, 80, DefaultSDConfig.Port)
	require.Equal(t, 10, DefaultSDConfig.RequestConcurrency)
}

func TestSDConfigUnmarshalYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		yaml         string
		validateFunc func(t *testing.T, cfg *SDConfig)
	}{
		{
			name: "EC2WithFlatFields",
			yaml: `role: ec2
region: us-west-2
port: 9100
filters:
  - name: instance-state-name
    values: [running]`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleEC2, cfg.Role)
				require.Equal(t, "us-west-2", cfg.Region)
				require.Equal(t, 9100, cfg.Port)
				require.Len(t, cfg.Filters, 1)
				require.Equal(t, "instance-state-name", cfg.Filters[0].Name)
				require.Equal(t, []string{"running"}, cfg.Filters[0].Values)
			},
		},
		{
			name: "ECSWithFlatFields",
			yaml: `role: ecs
region: us-east-1
port: 9200
clusters: ["some-cluster"]`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleECS, cfg.Role)
				require.Equal(t, "us-east-1", cfg.Region)
				require.Equal(t, 9200, cfg.Port)
				require.Equal(t, []string{"some-cluster"}, cfg.Clusters)
			},
		},
		{
			name: "LightsailWithFlatFields",
			yaml: `role: lightsail
region: eu-central-1
port: 9300`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleLightsail, cfg.Role)
				require.Equal(t, "eu-central-1", cfg.Region)
				require.Equal(t, 9300, cfg.Port)
			},
		},
		{
			name: "RDSWithFlatFields",
			yaml: `role: rds
region: us-east-1
port: 9400
filters:
  - name: engine
    values: [aurora-postgresql]`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleRDS, cfg.Role)
				require.Equal(t, "us-east-1", cfg.Region)
				require.Equal(t, 9400, cfg.Port)
				require.Len(t, cfg.Filters, 1)
				require.Equal(t, "engine", cfg.Filters[0].Name)
				require.Equal(t, []string{"aurora-postgresql"}, cfg.Filters[0].Values)
			},
		},
		{
			name: "MQWithFlatFields",
			yaml: `role: mq
region: us-west-1
port: 9700`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleMQ, cfg.Role)
				require.Equal(t, "us-west-1", cfg.Region)
				require.Equal(t, 9700, cfg.Port)
			},
		},
		{
			name: "MSKWithFlatFields",
			yaml: `role: msk
region: ap-south-1
port: 9500
clusters: ["some-cluster"]`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleMSK, cfg.Role)
				require.Equal(t, "ap-south-1", cfg.Region)
				require.Equal(t, 9500, cfg.Port)
				require.Equal(t, []string{"some-cluster"}, cfg.Clusters)
			},
		},
		{
			name: "ElasticacheWithFlatFields",
			yaml: `role: elasticache
region: eu-west-1
port: 9600`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, RoleElasticache, cfg.Role)
				require.Equal(t, "eu-west-1", cfg.Region)
				require.Equal(t, 9600, cfg.Port)
			},
		},
		{
			name: "DefaultsApplyWhenFieldsOmitted",
			yaml: `role: ec2
region: us-west-2`,
			validateFunc: func(t *testing.T, cfg *SDConfig) {
				require.Equal(t, DefaultSDConfig.Port, cfg.Port)
				require.Equal(t, DefaultSDConfig.RequestConcurrency, cfg.RequestConcurrency)
				require.Equal(t, DefaultSDConfig.RefreshInterval, cfg.RefreshInterval)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg SDConfig
			require.NoError(t, yaml.Unmarshal([]byte(tt.yaml), &cfg))
			tt.validateFunc(t, &cfg)
		})
	}
}

// TestMultipleSDConfigsDoNotShareState verifies that multiple AWS SD configs
// parsed from the same YAML document don't bleed state into each other. This
// was a bug where all configs pointed to the same global default, causing
// port and other settings from one job to overwrite settings in another job.
func TestMultipleSDConfigsDoNotShareState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		yaml         string
		validateFunc func(t *testing.T, cfg1, cfg2 *SDConfig)
	}{
		{
			name: "EC2MultipleJobsDifferentPorts",
			yaml: `
- role: ec2
  region: us-west-2
  port: 9100
  filters:
    - name: tag:Name
      values: [host-1]
- role: ec2
  region: us-west-2
  port: 9101
  filters:
    - name: tag:Name
      values: [host-2]`,
			validateFunc: func(t *testing.T, cfg1, cfg2 *SDConfig) {
				require.Equal(t, RoleEC2, cfg1.Role)
				require.Equal(t, RoleEC2, cfg2.Role)

				// Verify ports are different and not shared.
				require.Equal(t, 9100, cfg1.Port)
				require.Equal(t, 9101, cfg2.Port)

				// Verify filters are different and not shared.
				require.Len(t, cfg1.Filters, 1)
				require.Len(t, cfg2.Filters, 1)
				require.Equal(t, []string{"host-1"}, cfg1.Filters[0].Values)
				require.Equal(t, []string{"host-2"}, cfg2.Filters[0].Values)
			},
		},
		{
			name: "ECSMultipleJobsDifferentPorts",
			yaml: `
- role: ecs
  region: us-east-1
  port: 8080
  clusters: [cluster-a]
- role: ecs
  region: us-east-1
  port: 8081
  clusters: [cluster-b]`,
			validateFunc: func(t *testing.T, cfg1, cfg2 *SDConfig) {
				require.Equal(t, RoleECS, cfg1.Role)
				require.Equal(t, RoleECS, cfg2.Role)

				require.Equal(t, 8080, cfg1.Port)
				require.Equal(t, 8081, cfg2.Port)
				require.Equal(t, []string{"cluster-a"}, cfg1.Clusters)
				require.Equal(t, []string{"cluster-b"}, cfg2.Clusters)
			},
		},
		{
			name: "LightsailMultipleJobsDifferentPorts",
			yaml: `
- role: lightsail
  region: eu-west-1
  port: 7070
- role: lightsail
  region: eu-west-1
  port: 7071`,
			validateFunc: func(t *testing.T, cfg1, cfg2 *SDConfig) {
				require.Equal(t, RoleLightsail, cfg1.Role)
				require.Equal(t, RoleLightsail, cfg2.Role)

				require.Equal(t, 7070, cfg1.Port)
				require.Equal(t, 7071, cfg2.Port)
			},
		},
		{
			name: "MSKMultipleJobsDifferentPorts",
			yaml: `
- role: msk
  region: ap-south-1
  port: 6060
  clusters: ["cluster-1"]
- role: msk
  region: ap-south-1
  port: 6061
  clusters: ["cluster-2"]`,
			validateFunc: func(t *testing.T, cfg1, cfg2 *SDConfig) {
				require.Equal(t, RoleMSK, cfg1.Role)
				require.Equal(t, RoleMSK, cfg2.Role)

				require.Equal(t, 6060, cfg1.Port)
				require.Equal(t, []string{"cluster-1"}, cfg1.Clusters)
				require.Equal(t, 6061, cfg2.Port)
				require.Equal(t, []string{"cluster-2"}, cfg2.Clusters)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var configs []SDConfig
			require.NoError(t, yaml.Unmarshal([]byte(tt.yaml), &configs))
			require.Len(t, configs, 2)
			tt.validateFunc(t, &configs[0], &configs[1])
		})
	}
}

// getRandomRegion is a helper to return a pseudo-random AWS region for testing.
func getRandomRegion() string {
	regions := []string{
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
		"eu-west-1",
		"eu-west-2",
		"ap-southeast-1",
		"ap-southeast-2",
		"ap-northeast-1",
		"ap-northeast-2",
	}

	return regions[rand.IntN(len(regions))]
}

func TestLoadRegion(t *testing.T) {
	t.Run("with_env_region", func(t *testing.T) {
		randomRegion := getRandomRegion()
		t.Setenv("AWS_REGION", randomRegion)
		t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
		t.Setenv("AWS_CONFIG_FILE", "") // Ensure no config file is used
		t.Setenv("AWS_PROFILE", "")     // Ensure no profile file is used

		region, err := loadRegion(context.Background(), "")
		require.NoError(t, err)
		require.Equal(t, randomRegion, region)
	})

	t.Run("with_config_file_default_profile", func(t *testing.T) {
		randomRegion := getRandomRegion()

		// Create a temporary AWS config file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config")

		configContent := `[default]
region = ` + randomRegion + `
`

		err := os.WriteFile(configFile, []byte(configContent), 0o644)
		require.NoError(t, err)
		defer os.Remove(configFile)

		// Set up environment to use the config file
		t.Setenv("AWS_CONFIG_FILE", configFile)
		t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
		// Clear any region environment variables to force config file usage
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_PROFILE", "") // Ensure no profile file is used
		t.Setenv("AWS_DEFAULT_REGION", "")

		region, err := loadRegion(context.Background(), "")
		require.NoError(t, err)
		require.Equal(t, randomRegion, region)
	})

	t.Run("with_config_file_named_profile", func(t *testing.T) {
		randomRegion := getRandomRegion()

		// Create a temporary AWS config file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config")

		configContent := `[default]
region = ` + getRandomRegion() + `

[profile ` + randomRegion + `-profile]
region = ` + randomRegion + `
`

		err := os.WriteFile(configFile, []byte(configContent), 0o644)
		require.NoError(t, err)
		defer os.Remove(configFile)

		// Set up environment to use the config file
		t.Setenv("AWS_CONFIG_FILE", configFile)
		t.Setenv("AWS_PROFILE", randomRegion+"-profile")
		t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
		// Clear any region environment variables to force config file usage
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")

		region, err := loadRegion(context.Background(), "")
		require.NoError(t, err)
		require.Equal(t, randomRegion, region)
	})

	t.Run("with_specified_region", func(t *testing.T) {
		specifiedRegion := getRandomRegion()

		// Even with environment region set differently, specified region should take precedence
		t.Setenv("AWS_REGION", getRandomRegion())
		t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")

		region, err := loadRegion(context.Background(), specifiedRegion)
		require.NoError(t, err)
		require.Equal(t, specifiedRegion, region)
	})

	t.Run("imds_fallback", func(t *testing.T) {
		randomRegion := getRandomRegion()

		// Mock IMDS server that returns a region
		mockIMDS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle instance identity document (contains region info)
			if r.URL.Path == "/latest/dynamic/instance-identity/document" {
				imdsPayload := `{"region": "` + randomRegion + `"}`
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(imdsPayload))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockIMDS.Close()

		// Set up environment with no region but valid credentials
		// This will force fallback to IMDS
		t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
		// Unset any existing region
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		t.Setenv("AWS_CONFIG_FILE", "") // Ensure no config file is used
		t.Setenv("AWS_PROFILE", "")     // Ensure no profile file is used
		// Point IMDS to our mock server
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", mockIMDS.URL)

		region, err := loadRegion(context.Background(), "")
		require.NoError(t, err)
		require.Equal(t, randomRegion, region)
	})

	t.Run("imds_empty_region", func(t *testing.T) {
		// Mock IMDS server that returns empty region
		mockIMDS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle instance identity document with empty region
			if r.URL.Path == "/latest/dynamic/instance-identity/document" {
				imdsPayload := `{"region": ""}`
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(imdsPayload))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockIMDS.Close()

		// Set up environment with no region but valid credentials
		t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
		// Unset any existing region
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		t.Setenv("AWS_CONFIG_FILE", "") // Ensure no config file is used
		t.Setenv("AWS_PROFILE", "")     // Ensure no profile file is used
		// Point IMDS to our mock server
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", mockIMDS.URL)

		_, err := loadRegion(context.Background(), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get region from IMDS")
	})
}

// Regression test for issue #6092: parsing an AWS SD config must not call
// IMDS even when the region is omitted.
func TestAWSSDConfigUnmarshalYAML_NoRegionResolution(t *testing.T) {
	// Point IMDS at a black hole and wipe every other region source so any
	// accidental loadRegion call fails fast instead of waiting on IMDS.
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_PROFILE", "")

	yamls := map[string]string{
		"ec2":         `region: ""`,
		"ecs":         `region: ""`,
		"rds":         `region: ""`,
		"mq":          `region: ""`,
		"msk":         `region: ""`,
		"elasticache": `region: ""`,
		"lightsail":   `region: ""`,
	}

	for role, body := range yamls {
		t.Run(role, func(t *testing.T) {
			yamlStr := "role: " + role + "\n" + body + "\n"
			cfg := SDConfig{}
			err := yaml.Unmarshal([]byte(yamlStr), &cfg)
			require.NoError(t, err, "config parsing must not make network calls")
			require.Empty(t, cfg.Region, "region must remain empty after parse; resolution is deferred to SD init")
		})
	}
}

// TestRequestConcurrencyUnmarshalYAML checks that request_concurrency is
// rejected unless it is positive. A zero value makes errgroup.SetLimit block
// Go() forever on an unbuffered channel, which hangs the refresh regardless of
// the context deadline, and a negative one silently means "no limit at all".
func TestRequestConcurrencyUnmarshalYAML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		yaml        string
		expectedErr string
		expected    int
		wantDefault bool
	}{
		{
			name:        "Zero",
			yaml:        "request_concurrency: 0",
			expectedErr: "aws_sd: request_concurrency must be positive, got 0",
		},
		{
			name:        "Negative",
			yaml:        "request_concurrency: -1",
			expectedErr: "aws_sd: request_concurrency must be positive, got -1",
		},
		{
			name:     "Positive",
			yaml:     "request_concurrency: 5",
			expected: 5,
		},
		{
			name:        "Omitted",
			yaml:        "",
			wantDefault: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cfg SDConfig
			err := yaml.Unmarshal([]byte("role: ec2\nregion: us-west-2\n"+tt.yaml+"\n"), &cfg)

			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				return
			}

			require.NoError(t, err)
			expected := tt.expected
			if tt.wantDefault {
				expected = DefaultSDConfig.RequestConcurrency
			}
			require.Equal(t, expected, cfg.RequestConcurrency)
		})
	}
}

func TestSDConfigSetDirectory(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tests := []struct {
		name string
		yaml string
		role Role
	}{
		{
			name: "EC2",
			yaml: `
role: ec2
region: us-east-1
`,
			role: RoleEC2,
		},
		{
			name: "ECS",
			yaml: `
role: ecs
region: us-west-2
clusters: [test-cluster]
`,
			role: RoleECS,
		},
		{
			name: "Elasticache",
			yaml: `
role: elasticache
region: eu-west-1
`,
			role: RoleElasticache,
		},
		{
			name: "Lightsail",
			yaml: `
role: lightsail
region: ap-south-1
`,
			role: RoleLightsail,
		},
		{
			name: "MQ",
			yaml: `
role: mq
region: us-west-2
`,
			role: RoleMQ,
		},
		{
			name: "MSK",
			yaml: `
role: msk
region: us-east-2
`,
			role: RoleMSK,
		},
		{
			name: "RDS",
			yaml: `
role: rds
region: us-west-1
`,
			role: RoleRDS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg SDConfig
			err := yaml.Unmarshal([]byte(tt.yaml), &cfg)
			require.NoError(t, err)
			require.Equal(t, tt.role, cfg.Role)

			// Call SetDirectory - should not panic
			require.NotPanics(t, func() {
				cfg.SetDirectory(tmpDir)
			})
		})
	}
}

func TestSDConfigUnmarshalYAMLErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		yaml        string
		expectedErr string
	}{
		{
			name:        "UnknownRole",
			yaml:        "role: nope",
			expectedErr: `unknown AWS SD role "nope"`,
		},
		{
			name:        "EmptyFilterValues",
			yaml:        "role: ec2\nfilters:\n  - name: instance-state-name\n    values: []",
			expectedErr: "Filter values cannot be empty",
		},
		{
			name:        "MissingFilterValues",
			yaml:        "role: rds\nfilters:\n  - name: engine",
			expectedErr: "Filter values cannot be empty",
		},
		{
			name:        "InvalidHTTPClientConfig",
			yaml:        "role: ec2\nbasic_auth:\n  username: u\n  password: p\nauthorization:\n  credentials: c",
			expectedErr: "at most one of basic_auth, oauth2 & authorization must be configured",
		},
		{
			name:        "WrongFieldType",
			yaml:        "role: ec2\nport: not-a-number",
			expectedErr: "cannot unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cfg SDConfig
			err := yaml.Unmarshal([]byte(tt.yaml), &cfg)
			require.ErrorContains(t, err, tt.expectedErr)
		})
	}
}

func TestSDConfigRefreshMechanism(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{RoleEC2, RoleECS, RoleElasticache, RoleLightsail, RoleMQ, RoleMSK, RoleRDS} {
		t.Run(role.String(), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, role.String(), (&SDConfig{Role: role}).RefreshMechanism())
		})
	}
}

func TestSDConfigNewDiscovererMetrics(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	rmi := discovery.NewRefreshMetrics(reg)

	m := (&SDConfig{}).NewDiscovererMetrics(reg, rmi)
	require.IsType(t, &awsMetrics{}, m)
	require.NoError(t, m.Register())
	m.Unregister()
}

// awsAPIStub returns a fake AWS endpoint. Every request gets the given status
// and body; 4xx statuses are not retried by the AWS SDK so error paths stay fast.
func awsAPIStub(t *testing.T, status int, contentType, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setAWSTestEnv isolates the test from any ambient AWS configuration.
func setAWSTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "dummy")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "dummy")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "")
}

func newTestMetrics() *awsMetrics {
	return &awsMetrics{refreshMetrics: discovery.NewRefreshMetrics(prometheus.NewRegistry())}
}

func TestNewDiscovery(t *testing.T) {
	setAWSTestEnv(t)

	// Minimal successful responses for the credential check each role makes.
	const (
		jsonType = "application/json"
		xmlType  = "text/xml"
	)
	roles := []struct {
		role        Role
		contentType string
		body        string
	}{
		{RoleEC2, xmlType, `<DescribeAvailabilityZonesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><availabilityZoneInfo/></DescribeAvailabilityZonesResponse>`},
		{RoleECS, jsonType, `{}`},
		{RoleElasticache, xmlType, `<DescribeCacheClustersResponse xmlns="http://elasticache.amazonaws.com/doc/2015-02-02/"><DescribeCacheClustersResult/></DescribeCacheClustersResponse>`},
		{RoleLightsail, jsonType, `{}`},
		{RoleMQ, jsonType, `{}`},
		{RoleMSK, jsonType, `{}`},
		{RoleRDS, xmlType, `<DescribeDBClustersResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/"><DescribeDBClustersResult/></DescribeDBClustersResponse>`},
	}

	for _, r := range roles {
		t.Run(r.role.String()+"/success", func(t *testing.T) {
			srv := awsAPIStub(t, http.StatusOK, r.contentType, r.body)
			cfg := DefaultSDConfig
			cfg.Role = r.role
			cfg.Region = "us-east-1"
			cfg.Endpoint = srv.URL

			d, err := NewDiscovery(&cfg, discovery.DiscovererOptions{Metrics: newTestMetrics()})
			require.NoError(t, err)
			require.NotNil(t, d.awsDiscovery)
			require.Equal(t, "us-east-1", d.region)
		})

		t.Run(r.role.String()+"/credential_check_fails", func(t *testing.T) {
			srv := awsAPIStub(t, http.StatusBadRequest, jsonType, `{"__type":"AccessDeniedException","message":"denied"}`)
			cfg := DefaultSDConfig
			cfg.Role = r.role
			cfg.Region = "us-east-1"
			cfg.Endpoint = srv.URL

			d, err := NewDiscovery(&cfg, discovery.DiscovererOptions{Metrics: newTestMetrics()})
			require.Error(t, err)
			require.Nil(t, d)
		})
	}

	tests := []struct {
		name        string
		opts        discovery.DiscovererOptions
		mutate      func(*SDConfig)
		expectedErr string
	}{
		{
			name:        "InvalidMetricsType",
			opts:        discovery.DiscovererOptions{Metrics: nil},
			expectedErr: "invalid discovery metrics type for AWS SD",
		},
		{
			name:        "UnknownRole",
			opts:        discovery.DiscovererOptions{Metrics: newTestMetrics()},
			mutate:      func(c *SDConfig) { c.Role = "bogus" },
			expectedErr: "unknown role",
		},
		{
			name: "InvalidHTTPClientConfig",
			opts: discovery.DiscovererOptions{Metrics: newTestMetrics()},
			mutate: func(c *SDConfig) {
				c.HTTPClientConfig.TLSConfig = config.TLSConfig{CAFile: "/does/not/exist"}
			},
			expectedErr: "unable to read CA cert",
		},
		{
			name:        "RegionUnresolvable",
			opts:        discovery.DiscovererOptions{Metrics: newTestMetrics()},
			mutate:      func(c *SDConfig) { c.Region = "" },
			expectedErr: "could not determine AWS region",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultSDConfig
			cfg.Role = RoleEC2
			cfg.Region = "us-east-1"
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}

			d, err := NewDiscovery(&cfg, tt.opts)
			require.ErrorContains(t, err, tt.expectedErr)
			require.Nil(t, d)
		})
	}
}

func TestSDConfigNewDiscoverer(t *testing.T) {
	setAWSTestEnv(t)
	srv := awsAPIStub(t, http.StatusOK, "application/json", `{}`)

	cfg := DefaultSDConfig
	cfg.Role = RoleECS
	cfg.Region = "us-east-1"
	cfg.Endpoint = srv.URL

	d, err := cfg.NewDiscoverer(discovery.DiscovererOptions{Metrics: newTestMetrics()})
	require.NoError(t, err)
	require.NotNil(t, d)

	_, err = cfg.NewDiscoverer(discovery.DiscovererOptions{})
	require.Error(t, err)
}

func TestNewAWSCfg(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) *SDConfig
		check func(t *testing.T, d *Discovery, cfg *SDConfig)
	}{
		{
			name: "StaticCredentials",
			setup: func(*testing.T) *SDConfig {
				return &SDConfig{Region: "eu-west-1", AccessKey: "AKID", SecretKey: "SECRET"}
			},
			check: func(t *testing.T, d *Discovery, _ *SDConfig) {
				require.Equal(t, "eu-west-1", d.region)
			},
		},
		{
			name: "SharedConfigProfile",
			setup: func(t *testing.T) *SDConfig {
				f := filepath.Join(t.TempDir(), "config")
				require.NoError(t, os.WriteFile(f, []byte("[profile prom]\naws_access_key_id = PROFILEKEY\naws_secret_access_key = PROFILESECRET\n"), 0o600))
				t.Setenv("AWS_CONFIG_FILE", f)
				t.Setenv("AWS_ACCESS_KEY_ID", "")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "")
				return &SDConfig{Region: "us-east-1", Profile: "prom"}
			},
			check: func(t *testing.T, _ *Discovery, _ *SDConfig) {},
		},
		{
			name: "AssumeRoleWithExternalID",
			setup: func(*testing.T) *SDConfig {
				return &SDConfig{Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/prom", ExternalID: "ext"}
			},
			check: func(t *testing.T, _ *Discovery, _ *SDConfig) {},
		},
		{
			name: "UnknownProfile",
			setup: func(*testing.T) *SDConfig {
				return &SDConfig{Region: "us-east-1", Profile: "missing"}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setAWSTestEnv(t)
			sdCfg := tt.setup(t)
			sdCfg.HTTPClientConfig = config.DefaultHTTPClientConfig
			d := &Discovery{cfg: sdCfg}

			awsCfg, err := d.newAWSCfg(context.Background())
			if tt.check == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, sdCfg.Region, awsCfg.Region)
			require.NotNil(t, awsCfg.HTTPClient)
			require.NotNil(t, awsCfg.Credentials)
			tt.check(t, d, sdCfg)
		})
	}
}

// TestNewAWSCfgCredentialSources verifies which credentials end up in the config.
func TestNewAWSCfgCredentialSources(t *testing.T) {
	tests := []struct {
		name      string
		cfg       SDConfig
		profile   string
		expectKey string
	}{
		{
			name:      "StaticOverridesEnvironment",
			cfg:       SDConfig{Region: "us-east-1", AccessKey: "STATIC", SecretKey: "s"},
			expectKey: "STATIC",
		},
		{
			name:      "IncompleteStaticUsesEnvironment",
			cfg:       SDConfig{Region: "us-east-1", AccessKey: "STATIC"},
			expectKey: "dummy",
		},
		{
			name:      "ProfileCredentials",
			cfg:       SDConfig{Region: "us-east-1", Profile: "prom"},
			profile:   "[profile prom]\naws_access_key_id = PROFILEKEY\naws_secret_access_key = x\n",
			expectKey: "PROFILEKEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setAWSTestEnv(t)
			if tt.profile != "" {
				f := filepath.Join(t.TempDir(), "config")
				require.NoError(t, os.WriteFile(f, []byte(tt.profile), 0o600))
				t.Setenv("AWS_CONFIG_FILE", f)
			}
			tt.cfg.HTTPClientConfig = config.DefaultHTTPClientConfig
			d := &Discovery{cfg: &tt.cfg}

			awsCfg, err := d.newAWSCfg(context.Background())
			require.NoError(t, err)
			creds, err := awsCfg.Credentials.Retrieve(context.Background())
			require.NoError(t, err)
			require.Equal(t, tt.expectKey, creds.AccessKeyID)
		})
	}
}

type fakeAWSDiscovery struct {
	groups []*targetgroup.Group
	err    error
}

func (f fakeAWSDiscovery) refresh(context.Context) ([]*targetgroup.Group, error) {
	return f.groups, f.err
}

func TestRefreshTargets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		fake   fakeAWSDiscovery
		expErr string
	}{
		{
			name: "DelegatesToRoleDiscovery",
			fake: fakeAWSDiscovery{groups: []*targetgroup.Group{{Source: "ec2"}}},
		},
		{
			name:   "PropagatesError",
			fake:   fakeAWSDiscovery{err: errors.New("api down")},
			expErr: "api down",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &Discovery{awsDiscovery: tt.fake}
			groups, err := d.refreshTargets(context.Background())
			if tt.expErr != "" {
				require.EqualError(t, err, tt.expErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.fake.groups, groups)
		})
	}
}

func TestLoadRegionErrors(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T)
		expectedErr string
	}{
		{
			name: "UnknownProfile",
			setup: func(t *testing.T) {
				f := filepath.Join(t.TempDir(), "config")
				require.NoError(t, os.WriteFile(f, []byte("[default]\nregion = us-east-1\n"), 0o600))
				t.Setenv("AWS_CONFIG_FILE", f)
				t.Setenv("AWS_PROFILE", "missing")
			},
			expectedErr: "failed to load AWS config",
		},
		{
			name:        "IMDSUnreachable",
			setup:       func(*testing.T) {},
			expectedErr: "failed to get region from IMDS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setAWSTestEnv(t)
			tt.setup(t)
			_, err := loadRegion(context.Background(), "")
			require.ErrorContains(t, err, tt.expectedErr)
			require.ErrorContains(t, err, "could not determine AWS region")
		})
	}
}
