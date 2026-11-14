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
	"maps"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/discovery/targetgroup"
)

// mqDataStore holds the fake MQ API responses used by mockMQClient.
type mqDataStore struct {
	region  string
	brokers []*mq.DescribeBrokerOutput
}

func TestMQDiscoveryRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// baseLabels returns the broker-level labels shared by every target of the
	// single broker used in these test cases.
	baseLabels := func() model.LabelSet {
		return model.LabelSet{
			"__meta_mq_authentication_strategy": model.LabelValue("SIMPLE"),
			"__meta_mq_broker_arn":              model.LabelValue("arn:aws:mq:us-west-2:123456789012:broker:test-broker:b-abc-123"),
			"__meta_mq_broker_id":               model.LabelValue("b-abc-123"),
			"__meta_mq_broker_name":             model.LabelValue("test-broker"),
			"__meta_mq_broker_state":            model.LabelValue("RUNNING"),
			"__meta_mq_engine_type":             model.LabelValue("ACTIVEMQ"),
			"__meta_mq_engine_version":          model.LabelValue("5.18.4"),
			"__meta_mq_security_groups":         model.LabelValue("sg-12345"),
			"__meta_mq_storage_type":            model.LabelValue("EFS"),
			"__meta_mq_subnet_ids":              model.LabelValue("subnet-12345,subnet-67890"),
		}
	}

	// withLabels returns the broker-level labels extended with the given
	// deployment mode and per-instance labels.
	withLabels := func(deploymentMode string, extra model.LabelSet) model.LabelSet {
		labels := baseLabels()
		labels["__meta_mq_deployment_mode"] = model.LabelValue(deploymentMode)
		maps.Copy(labels, extra)
		return labels
	}

	for _, tt := range []struct {
		name     string
		mqData   *mqDataStore
		expected []*targetgroup.Group
	}{
		{
			// A SINGLE_INSTANCE broker has exactly one broker instance and so
			// produces exactly one target.
			name: "SingleInstanceBroker",
			mqData: &mqDataStore{
				region: "us-west-2",
				brokers: []*mq.DescribeBrokerOutput{
					{
						AuthenticationStrategy: types.AuthenticationStrategySimple,
						BrokerArn:              strptr("arn:aws:mq:us-west-2:123456789012:broker:test-broker:b-abc-123"),
						BrokerId:               strptr("b-abc-123"),
						BrokerName:             strptr("test-broker"),
						BrokerState:            types.BrokerStateRunning,
						DeploymentMode:         types.DeploymentModeSingleInstance,
						EngineType:             types.EngineTypeActivemq,
						EngineVersion:          strptr("5.18.4"),
						SecurityGroups:         []string{"sg-12345"},
						StorageType:            types.BrokerStorageTypeEfs,
						SubnetIds:              []string{"subnet-12345", "subnet-67890"},
						BrokerInstances: []types.BrokerInstance{
							{
								IpAddress: strptr("10.0.1.10"),
								Endpoints: []string{
									"ssl://b-abc-123-1.mq.us-west-2.amazonaws.com:61617",
									"https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162",
								},
							},
						},
					},
				},
			},
			expected: []*targetgroup.Group{
				{
					Source: "us-west-2",
					Targets: []model.LabelSet{
						withLabels("SINGLE_INSTANCE", model.LabelSet{
							model.AddressLabel:                     model.LabelValue("b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_endpoint":   model.LabelValue("https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_ip_address": model.LabelValue("10.0.1.10"),
						}),
					},
				},
			},
		},
		{
			// Data replication mode, logs (enabled flag and log group, both
			// current and pending), pending security groups and LDAP hosts must
			// all be read from their correct source fields and, where they are
			// lists, joined consistently with the non-pending equivalents.
			// Critically, when both a current and a pending value are set for
			// data replication metadata, LDAP server metadata and logs, the two
			// must produce distinct labels rather than the pending value
			// silently overwriting the current one under the same label name.
			name: "DataReplicationLogsAndListFormattingLabels",
			mqData: &mqDataStore{
				region: "us-west-2",
				brokers: []*mq.DescribeBrokerOutput{
					{
						AuthenticationStrategy:     types.AuthenticationStrategySimple,
						BrokerArn:                  strptr("arn:aws:mq:us-west-2:123456789012:broker:test-broker:b-abc-123"),
						BrokerId:                   strptr("b-abc-123"),
						BrokerName:                 strptr("test-broker"),
						BrokerState:                types.BrokerStateRunning,
						DeploymentMode:             types.DeploymentModeSingleInstance,
						EngineType:                 types.EngineTypeActivemq,
						EngineVersion:              strptr("5.18.4"),
						SecurityGroups:             []string{"sg-12345"},
						StorageType:                types.BrokerStorageTypeEfs,
						SubnetIds:                  []string{"subnet-12345", "subnet-67890"},
						DataReplicationMode:        types.DataReplicationModeCrdr,
						PendingDataReplicationMode: types.DataReplicationModeNone,
						DataReplicationMetadata: &types.DataReplicationMetadataOutput{
							DataReplicationRole: strptr("PRIMARY"),
							DataReplicationCounterpart: &types.DataReplicationCounterpart{
								BrokerId: strptr("b-current-counterpart"),
								Region:   strptr("us-west-2"),
							},
						},
						PendingDataReplicationMetadata: &types.DataReplicationMetadataOutput{
							DataReplicationRole: strptr("REPLICA"),
							DataReplicationCounterpart: &types.DataReplicationCounterpart{
								BrokerId: strptr("b-pending-counterpart"),
								Region:   strptr("us-east-1"),
							},
						},
						PendingSecurityGroups: []string{"sg-12345", "sg-67890"},
						Logs: &types.LogsSummary{
							Audit:           aws.Bool(true),
							AuditLogGroup:   strptr("/aws/amazonmq/broker/b-abc-123/audit"),
							General:         aws.Bool(true),
							GeneralLogGroup: strptr("/aws/amazonmq/broker/b-abc-123/general"),
							Pending: &types.PendingLogs{
								Audit:   aws.Bool(false),
								General: aws.Bool(true),
							},
						},
						LdapServerMetadata: &types.LdapServerMetadataOutput{
							Hosts: []string{"ldap1.example.com", "ldap2.example.com"},
						},
						PendingLdapServerMetadata: &types.LdapServerMetadataOutput{
							Hosts: []string{"ldap3.example.com"},
						},
						BrokerInstances: []types.BrokerInstance{
							{
								IpAddress: strptr("10.0.1.10"),
								Endpoints: []string{
									"https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162",
								},
							},
						},
					},
				},
			},
			expected: []*targetgroup.Group{
				{
					Source: "us-west-2",
					Targets: []model.LabelSet{
						withLabels("SINGLE_INSTANCE", model.LabelSet{
							model.AddressLabel:                                                                   model.LabelValue("b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_endpoint":                                                 model.LabelValue("https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_ip_address":                                               model.LabelValue("10.0.1.10"),
							"__meta_mq_data_replication_mode":                                                    model.LabelValue("CRDR"),
							"__meta_mq_pending_data_replication_mode":                                            model.LabelValue("NONE"),
							"__meta_mq_data_replication_metadata_data_replication_role":                          model.LabelValue("PRIMARY"),
							"__meta_mq_data_replication_metadata_data_replication_counterpart_broker_id":         model.LabelValue("b-current-counterpart"),
							"__meta_mq_data_replication_metadata_data_replication_counterpart_region":            model.LabelValue("us-west-2"),
							"__meta_mq_pending_data_replication_metadata_data_replication_role":                  model.LabelValue("REPLICA"),
							"__meta_mq_pending_data_replication_metadata_data_replication_counterpart_broker_id": model.LabelValue("b-pending-counterpart"),
							"__meta_mq_pending_data_replication_metadata_data_replication_counterpart_region":    model.LabelValue("us-east-1"),
							"__meta_mq_pending_security_groups":                                                  model.LabelValue("sg-12345,sg-67890"),
							"__meta_mq_logs_audit":                                                               model.LabelValue("true"),
							"__meta_mq_logs_audit_log_group":                                                     model.LabelValue("/aws/amazonmq/broker/b-abc-123/audit"),
							"__meta_mq_logs_general":                                                             model.LabelValue("true"),
							"__meta_mq_logs_general_log_group":                                                   model.LabelValue("/aws/amazonmq/broker/b-abc-123/general"),
							"__meta_mq_logs_pending_audit":                                                       model.LabelValue("false"),
							"__meta_mq_logs_pending_general":                                                     model.LabelValue("true"),
							"__meta_mq_ldap_server_metadata_hosts":                                               model.LabelValue("ldap1.example.com,ldap2.example.com"),
							"__meta_mq_pending_ldap_server_metadata_hosts":                                       model.LabelValue("ldap3.example.com"),
						}),
					},
				},
			},
		},
		{
			// An ACTIVE_STANDBY_MULTI_AZ broker has two broker instances, each
			// with its own host and port, and must produce one target per
			// instance rather than only the last one.
			name: "ActiveStandbyMultiAZBrokerYieldsOneTargetPerInstance",
			mqData: &mqDataStore{
				region: "us-west-2",
				brokers: []*mq.DescribeBrokerOutput{
					{
						AuthenticationStrategy: types.AuthenticationStrategySimple,
						BrokerArn:              strptr("arn:aws:mq:us-west-2:123456789012:broker:test-broker:b-abc-123"),
						BrokerId:               strptr("b-abc-123"),
						BrokerName:             strptr("test-broker"),
						BrokerState:            types.BrokerStateRunning,
						DeploymentMode:         types.DeploymentModeActiveStandbyMultiAz,
						EngineType:             types.EngineTypeActivemq,
						EngineVersion:          strptr("5.18.4"),
						SecurityGroups:         []string{"sg-12345"},
						StorageType:            types.BrokerStorageTypeEfs,
						SubnetIds:              []string{"subnet-12345", "subnet-67890"},
						BrokerInstances: []types.BrokerInstance{
							{
								IpAddress: strptr("10.0.1.10"),
								Endpoints: []string{
									"ssl://b-abc-123-1.mq.us-west-2.amazonaws.com:61617",
									"https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162",
								},
							},
							{
								IpAddress: strptr("10.0.2.20"),
								Endpoints: []string{
									"ssl://b-abc-123-2.mq.us-west-2.amazonaws.com:61617",
									"https://b-abc-123-2.mq.us-west-2.amazonaws.com:8162",
								},
							},
						},
					},
				},
			},
			expected: []*targetgroup.Group{
				{
					Source: "us-west-2",
					Targets: []model.LabelSet{
						withLabels("ACTIVE_STANDBY_MULTI_AZ", model.LabelSet{
							model.AddressLabel:                     model.LabelValue("b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_endpoint":   model.LabelValue("https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_ip_address": model.LabelValue("10.0.1.10"),
						}),
						withLabels("ACTIVE_STANDBY_MULTI_AZ", model.LabelSet{
							model.AddressLabel:                     model.LabelValue("b-abc-123-2.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_endpoint":   model.LabelValue("https://b-abc-123-2.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_ip_address": model.LabelValue("10.0.2.20"),
						}),
					},
				},
			},
		},
		{
			// An instance without an https endpoint has no address to scrape and
			// must be skipped without leaking its IP address onto, or inheriting
			// the endpoint of, a sibling instance.
			name: "InstanceWithoutHTTPSEndpointIsSkipped",
			mqData: &mqDataStore{
				region: "us-west-2",
				brokers: []*mq.DescribeBrokerOutput{
					{
						AuthenticationStrategy: types.AuthenticationStrategySimple,
						BrokerArn:              strptr("arn:aws:mq:us-west-2:123456789012:broker:test-broker:b-abc-123"),
						BrokerId:               strptr("b-abc-123"),
						BrokerName:             strptr("test-broker"),
						BrokerState:            types.BrokerStateRunning,
						DeploymentMode:         types.DeploymentModeActiveStandbyMultiAz,
						EngineType:             types.EngineTypeActivemq,
						EngineVersion:          strptr("5.18.4"),
						SecurityGroups:         []string{"sg-12345"},
						StorageType:            types.BrokerStorageTypeEfs,
						SubnetIds:              []string{"subnet-12345", "subnet-67890"},
						BrokerInstances: []types.BrokerInstance{
							{
								IpAddress: strptr("10.0.1.10"),
								Endpoints: []string{
									"ssl://b-abc-123-1.mq.us-west-2.amazonaws.com:61617",
									"https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162",
								},
							},
							{
								IpAddress: strptr("10.0.2.20"),
								Endpoints: []string{
									"ssl://b-abc-123-2.mq.us-west-2.amazonaws.com:61617",
								},
							},
						},
					},
				},
			},
			expected: []*targetgroup.Group{
				{
					Source: "us-west-2",
					Targets: []model.LabelSet{
						withLabels("ACTIVE_STANDBY_MULTI_AZ", model.LabelSet{
							model.AddressLabel:                     model.LabelValue("b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_endpoint":   model.LabelValue("https://b-abc-123-1.mq.us-west-2.amazonaws.com:8162"),
							"__meta_mq_broker_instance_ip_address": model.LabelValue("10.0.1.10"),
						}),
					},
				},
			},
		},
		{
			// A RabbitMQ CLUSTER_MULTI_AZ broker reports its three nodes as a
			// single BrokerInstance with one https endpoint per node (same host,
			// distinct ports), rather than as three separate BrokerInstances.
			// Each https endpoint must still become its own target.
			name: "RabbitMQClusterMultiAZBrokerYieldsOneTargetPerNodeEndpoint",
			mqData: &mqDataStore{
				region: "us-east-1",
				brokers: []*mq.DescribeBrokerOutput{
					{
						AuthenticationStrategy: types.AuthenticationStrategySimple,
						BrokerArn:              strptr("arn:aws:mq:us-east-1:123456789012:broker:test-broker:b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
						BrokerId:               strptr("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
						BrokerName:             strptr("test-broker"),
						BrokerState:            types.BrokerStateRunning,
						DeploymentMode:         types.DeploymentModeClusterMultiAz,
						EngineType:             types.EngineTypeRabbitmq,
						EngineVersion:          strptr("3.13.7"),
						SecurityGroups:         []string{"sg-12345"},
						StorageType:            types.BrokerStorageTypeEbs,
						SubnetIds:              []string{"subnet-12345", "subnet-67890"},
						BrokerInstances: []types.BrokerInstance{
							{
								// RabbitMQ brokers do not set IpAddress.
								ConsoleURL: strptr("https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws"),
								Endpoints: []string{
									"https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16001",
									"amqps://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:5671",
									"https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16003",
									"https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16002",
								},
							},
						},
					},
				},
			},
			expected: []*targetgroup.Group{
				{
					Source: "us-east-1",
					Targets: []model.LabelSet{
						{
							"__meta_mq_authentication_strategy":  model.LabelValue("SIMPLE"),
							"__meta_mq_broker_arn":               model.LabelValue("arn:aws:mq:us-east-1:123456789012:broker:test-broker:b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
							"__meta_mq_broker_id":                model.LabelValue("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
							"__meta_mq_broker_name":              model.LabelValue("test-broker"),
							"__meta_mq_broker_state":             model.LabelValue("RUNNING"),
							"__meta_mq_deployment_mode":          model.LabelValue("CLUSTER_MULTI_AZ"),
							"__meta_mq_engine_type":              model.LabelValue("RABBITMQ"),
							"__meta_mq_engine_version":           model.LabelValue("3.13.7"),
							"__meta_mq_security_groups":          model.LabelValue("sg-12345"),
							"__meta_mq_storage_type":             model.LabelValue("EBS"),
							"__meta_mq_subnet_ids":               model.LabelValue("subnet-12345,subnet-67890"),
							model.AddressLabel:                   model.LabelValue("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16001"),
							"__meta_mq_broker_instance_endpoint": model.LabelValue("https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16001"),
						},
						{
							"__meta_mq_authentication_strategy":  model.LabelValue("SIMPLE"),
							"__meta_mq_broker_arn":               model.LabelValue("arn:aws:mq:us-east-1:123456789012:broker:test-broker:b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
							"__meta_mq_broker_id":                model.LabelValue("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
							"__meta_mq_broker_name":              model.LabelValue("test-broker"),
							"__meta_mq_broker_state":             model.LabelValue("RUNNING"),
							"__meta_mq_deployment_mode":          model.LabelValue("CLUSTER_MULTI_AZ"),
							"__meta_mq_engine_type":              model.LabelValue("RABBITMQ"),
							"__meta_mq_engine_version":           model.LabelValue("3.13.7"),
							"__meta_mq_security_groups":          model.LabelValue("sg-12345"),
							"__meta_mq_storage_type":             model.LabelValue("EBS"),
							"__meta_mq_subnet_ids":               model.LabelValue("subnet-12345,subnet-67890"),
							model.AddressLabel:                   model.LabelValue("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16002"),
							"__meta_mq_broker_instance_endpoint": model.LabelValue("https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16002"),
						},
						{
							"__meta_mq_authentication_strategy":  model.LabelValue("SIMPLE"),
							"__meta_mq_broker_arn":               model.LabelValue("arn:aws:mq:us-east-1:123456789012:broker:test-broker:b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
							"__meta_mq_broker_id":                model.LabelValue("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73"),
							"__meta_mq_broker_name":              model.LabelValue("test-broker"),
							"__meta_mq_broker_state":             model.LabelValue("RUNNING"),
							"__meta_mq_deployment_mode":          model.LabelValue("CLUSTER_MULTI_AZ"),
							"__meta_mq_engine_type":              model.LabelValue("RABBITMQ"),
							"__meta_mq_engine_version":           model.LabelValue("3.13.7"),
							"__meta_mq_security_groups":          model.LabelValue("sg-12345"),
							"__meta_mq_storage_type":             model.LabelValue("EBS"),
							"__meta_mq_subnet_ids":               model.LabelValue("subnet-12345,subnet-67890"),
							model.AddressLabel:                   model.LabelValue("b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16003"),
							"__meta_mq_broker_instance_endpoint": model.LabelValue("https://b-9046eed6-7807-4ef5-9f74-6f4071ec8b73.mq.us-east-1.on.aws:16003"),
						},
					},
				},
			},
		},
		{
			// A broker that is still being created reports no broker instances
			// and must not produce an address-less target.
			name: "BrokerWithoutInstancesYieldsNoTargets",
			mqData: &mqDataStore{
				region: "us-west-2",
				brokers: []*mq.DescribeBrokerOutput{
					{
						AuthenticationStrategy: types.AuthenticationStrategySimple,
						BrokerArn:              strptr("arn:aws:mq:us-west-2:123456789012:broker:test-broker:b-abc-123"),
						BrokerId:               strptr("b-abc-123"),
						BrokerName:             strptr("test-broker"),
						BrokerState:            types.BrokerStateCreationInProgress,
						DeploymentMode:         types.DeploymentModeSingleInstance,
						EngineType:             types.EngineTypeActivemq,
						EngineVersion:          strptr("5.18.4"),
						SecurityGroups:         []string{"sg-12345"},
						StorageType:            types.BrokerStorageTypeEfs,
						SubnetIds:              []string{"subnet-12345", "subnet-67890"},
					},
				},
			},
			expected: []*targetgroup.Group{
				{
					Source:  "us-west-2",
					Targets: nil,
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newMockMQClient(tt.mqData)
			d := &MQDiscovery{
				Discovery: Discovery{
					logger: promslog.NewNopLogger(),
					cfg: &SDConfig{
						Role:               RoleMQ,
						Region:             tt.mqData.region,
						RequestConcurrency: 10,
					},
					region: tt.mqData.region,
				},
				mq: mqClientAdapter{
					describeBroker: client.DescribeBroker,
					listBrokers:    client.ListBrokers,
				},
			}

			groups, err := d.refresh(ctx)
			require.NoError(t, err)

			// Targets are appended from goroutines, so ordering is not deterministic.
			for _, group := range groups {
				sortTargets(group.Targets)
			}
			for _, group := range tt.expected {
				sortTargets(group.Targets)
			}

			require.Equal(t, tt.expected, groups)
		})
	}
}

// sortTargets sorts targets by their address label so that assertions do not
// depend on the order in which the refresh goroutines complete.
func sortTargets(targets []model.LabelSet) {
	sort.Slice(targets, func(i, j int) bool {
		return targets[i][model.AddressLabel] < targets[j][model.AddressLabel]
	})
}

// MQ client mock.
type mockMQClient struct {
	mqData mqDataStore
}

func newMockMQClient(mqData *mqDataStore) *mockMQClient {
	return &mockMQClient{
		mqData: *mqData,
	}
}

func (m *mockMQClient) DescribeBroker(_ context.Context, input *mq.DescribeBrokerInput, _ ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error) {
	inputID := aws.ToString(input.BrokerId)
	for _, broker := range m.mqData.brokers {
		if aws.ToString(broker.BrokerId) == inputID {
			return broker, nil
		}
	}

	return nil, fmt.Errorf("broker not found: %s", inputID)
}

func (m *mockMQClient) ListBrokers(_ context.Context, _ *mq.ListBrokersInput, _ ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
	summaries := make([]types.BrokerSummary, 0, len(m.mqData.brokers))
	for _, broker := range m.mqData.brokers {
		summaries = append(summaries, types.BrokerSummary{
			BrokerArn:      broker.BrokerArn,
			BrokerId:       broker.BrokerId,
			BrokerName:     broker.BrokerName,
			BrokerState:    broker.BrokerState,
			DeploymentMode: broker.DeploymentMode,
			EngineType:     broker.EngineType,
		})
	}

	return &mq.ListBrokersOutput{
		BrokerSummaries: summaries,
	}, nil
}

func TestMQDiscoveryAPIErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	apiErr := errors.New("api down")

	tests := []struct {
		name        string
		adapter     mqClientAdapter
		expectedErr string
	}{
		{
			name: "ListBrokersFails",
			adapter: mqClientAdapter{
				listBrokers: func(context.Context, *mq.ListBrokersInput, ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
					return nil, apiErr
				},
			},
			expectedErr: "error listing brokers: api down",
		},
		{
			name: "ListBrokersFailsOnSecondPage",
			adapter: mqClientAdapter{
				listBrokers: func(_ context.Context, in *mq.ListBrokersInput, _ ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
					if in.NextToken == nil {
						return &mq.ListBrokersOutput{
							BrokerSummaries: []types.BrokerSummary{{BrokerId: aws.String("b-1")}},
							NextToken:       aws.String("page2"),
						}, nil
					}
					return nil, apiErr
				},
			},
			expectedErr: "error listing brokers: api down",
		},
		{
			name: "DescribeBrokerFails",
			adapter: mqClientAdapter{
				listBrokers: func(context.Context, *mq.ListBrokersInput, ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
					return &mq.ListBrokersOutput{BrokerSummaries: []types.BrokerSummary{{BrokerId: aws.String("b-1")}}}, nil
				},
				describeBroker: func(context.Context, *mq.DescribeBrokerInput, ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error) {
					return nil, apiErr
				},
			},
			expectedErr: "error describing brokers: error describing broker b-1: api down",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &MQDiscovery{
				Discovery: Discovery{
					logger: promslog.NewNopLogger(),
					cfg:    &SDConfig{Role: RoleMQ, RequestConcurrency: 2},
					region: "us-east-1",
				},
				mq: tt.adapter,
			}
			groups, err := d.refresh(ctx)
			require.EqualError(t, err, tt.expectedErr)
			require.Nil(t, groups)
		})
	}
}

func TestMQDiscoveryListBrokersPagination(t *testing.T) {
	t.Parallel()

	pages := map[string]*mq.ListBrokersOutput{
		"":      {BrokerSummaries: []types.BrokerSummary{{BrokerId: aws.String("b-1")}, {BrokerId: aws.String("b-2")}}, NextToken: aws.String("p2")},
		"p2":    {BrokerSummaries: []types.BrokerSummary{{BrokerId: aws.String("b-3")}}, NextToken: aws.String("p3")},
		"p3":    {BrokerSummaries: nil},
		"other": nil,
	}
	var calls int
	d := &MQDiscovery{
		Discovery: Discovery{cfg: &SDConfig{RequestConcurrency: 1}},
		mq: mqClientAdapter{
			listBrokers: func(_ context.Context, in *mq.ListBrokersInput, _ ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
				calls++
				require.Equal(t, int32(100), aws.ToInt32(in.MaxResults))
				return pages[aws.ToString(in.NextToken)], nil
			},
		},
	}

	ids, err := d.listBrokers(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"b-1", "b-2", "b-3"}, ids)
	require.Equal(t, 3, calls)
}

func TestMQLabelHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      model.LabelSet
		expected model.LabelSet
	}{
		{
			name:     "ConfigurationsNil",
			got:      mqConfigurationLabels(nil),
			expected: model.LabelSet{},
		},
		{
			name:     "ConfigurationsCurrentEmpty",
			got:      mqConfigurationLabels(&types.Configurations{Current: &types.ConfigurationId{}}),
			expected: model.LabelSet{},
		},
		{
			name: "ConfigurationsCurrent",
			got:  mqConfigurationLabels(&types.Configurations{Current: &types.ConfigurationId{Id: aws.String("c-1"), Revision: aws.Int32(3)}}),
			expected: model.LabelSet{
				mqLabelConfigurationsCurrentID:       "c-1",
				mqLabelConfigurationsCurrentRevision: "3",
			},
		},
		{
			name:     "EncryptionNil",
			got:      mqEncryptionOptionsLabels(nil),
			expected: model.LabelSet{},
		},
		{
			name:     "EncryptionEmpty",
			got:      mqEncryptionOptionsLabels(&types.EncryptionOptions{}),
			expected: model.LabelSet{},
		},
		{
			name: "EncryptionFull",
			got:  mqEncryptionOptionsLabels(&types.EncryptionOptions{UseAwsOwnedKey: aws.Bool(false), KmsKeyId: aws.String("key-1")}),
			expected: model.LabelSet{
				mqLabelEncryptionOptionsUseAwsOwned: "false",
				mqLabelEncryptionOptionsKmsKeyID:    "key-1",
			},
		},
		{
			name:     "MaintenanceWindowNil",
			got:      mqMaintenanceWindowStartTimeLabels(nil),
			expected: model.LabelSet{},
		},
		{
			name:     "MaintenanceWindowEmpty",
			got:      mqMaintenanceWindowStartTimeLabels(&types.WeeklyStartTime{}),
			expected: model.LabelSet{},
		},
		{
			name: "MaintenanceWindowFull",
			got: mqMaintenanceWindowStartTimeLabels(&types.WeeklyStartTime{
				DayOfWeek: types.DayOfWeekMonday,
				TimeOfDay: aws.String("02:00"),
				TimeZone:  aws.String("UTC"),
			}),
			expected: model.LabelSet{
				mqLabelMaintenanceWindowStartTimeDayOfWeek: "MONDAY",
				mqLabelMaintenanceWindowStartTimeTimeOfDay: "02:00",
				mqLabelMaintenanceWindowStartTimeTimeZone:  "UTC",
			},
		},
		{
			name:     "DataReplicationNil",
			got:      mqDataReplicationMetadataLabels(nil, false),
			expected: model.LabelSet{},
		},
		{
			name: "DataReplicationCurrent",
			got: mqDataReplicationMetadataLabels(&types.DataReplicationMetadataOutput{
				DataReplicationRole:        aws.String("LEADER"),
				DataReplicationCounterpart: &types.DataReplicationCounterpart{BrokerId: aws.String("b-2"), Region: aws.String("eu-west-1")},
			}, false),
			expected: model.LabelSet{
				mqLabelDataReplicationMetadataDataReplicationRole:                "LEADER",
				mqLabelDataReplicationMetadataDataReplicationCounterpartBrokerID: "b-2",
				mqLabelDataReplicationMetadataDataReplicationCounterpartRegion:   "eu-west-1",
			},
		},
		{
			name: "DataReplicationPending",
			got: mqDataReplicationMetadataLabels(&types.DataReplicationMetadataOutput{
				DataReplicationRole:        aws.String("FOLLOWER"),
				DataReplicationCounterpart: &types.DataReplicationCounterpart{BrokerId: aws.String("b-3"), Region: aws.String("us-east-2")},
			}, true),
			expected: model.LabelSet{
				mqLabelPendingDataReplicationMetadataDataReplicationRole:                "FOLLOWER",
				mqLabelPendingDataReplicationMetadataDataReplicationCounterpartBrokerID: "b-3",
				mqLabelPendingDataReplicationMetadataDataReplicationCounterpartRegion:   "us-east-2",
			},
		},
		{
			name:     "LdapNil",
			got:      mqLdapServerMetadataLabels(nil, false),
			expected: model.LabelSet{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, tt.got)
		})
	}
}
