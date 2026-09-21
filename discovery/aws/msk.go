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
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/prometheus/common/model"
	"golang.org/x/sync/errgroup"

	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/util/strutil"
)

type NodeType string

const (
	NodeTypeBroker     NodeType = "BROKER"
	NodeTypeController NodeType = "CONTROLLER"
)

const (
	mskLabel = model.MetaLabelPrefix + "msk_"

	// Cluster labels.
	mskLabelCluster                      = mskLabel + "cluster_"
	mskLabelClusterName                  = mskLabelCluster + "name"
	mskLabelClusterARN                   = mskLabelCluster + "arn"
	mskLabelClusterState                 = mskLabelCluster + "state"
	mskLabelClusterType                  = mskLabelCluster + "type"
	mskLabelClusterVersion               = mskLabelCluster + "version"
	mskLabelClusterJmxExporterEnabled    = mskLabelCluster + "jmx_exporter_enabled"
	mskLabelClusterConfigurationARN      = mskLabelCluster + "configuration_arn"
	mskLabelClusterConfigurationRevision = mskLabelCluster + "configuration_revision"
	mskLabelClusterKafkaVersion          = mskLabelCluster + "kafka_version"
	mskLabelClusterTags                  = mskLabelCluster + "tag_"

	// Node labels.
	mskLabelNode             = mskLabel + "node_"
	mskLabelNodeType         = mskLabelNode + "type"
	mskLabelNodeARN          = mskLabelNode + "arn"
	mskLabelNodeAddedTime    = mskLabelNode + "added_time"
	mskLabelNodeInstanceType = mskLabelNode + "instance_type"
	mskLabelNodeAttachedENI  = mskLabelNode + "attached_eni"

	// Broker labels.
	mskLabelBroker                    = mskLabel + "broker_"
	mskLabelBrokerEndpointIndex       = mskLabelBroker + "endpoint_index"
	mskLabelBrokerID                  = mskLabelBroker + "id"
	mskLabelBrokerClientSubnet        = mskLabelBroker + "client_subnet"
	mskLabelBrokerClientVPCIP         = mskLabelBroker + "client_vpc_ip"
	mskLabelBrokerNodeExporterEnabled = mskLabelBroker + "node_exporter_enabled"

	// Controller labels.
	mskLabelController              = mskLabel + "controller_"
	mskLabelControllerEndpointIndex = mskLabelController + "endpoint_index"
)

// MSKDiscovery is the AWS discovery implementation for MSK (Kafka).
// It implements the awsRefresher interface, which allows it to refresh AWS targets for MSK.
type MSKDiscovery struct {
	Discovery
	msk mskClientAdapter
}

var _ awsDiscovery = (*MSKDiscovery)(nil)

// mskClientAdapter captures only the MSK (Kafka) API calls AWS discovery uses
// as method-value closures, keeping the concrete *kafka.Client out of any
// interface-boxed struct field. See ec2ClientAdapter for the full rationale:
// this stops the linker from retaining the entire MSK API surface (~1.4 MB).
type mskClientAdapter struct {
	describeClusterV2 func(context.Context, *kafka.DescribeClusterV2Input, ...func(*kafka.Options)) (*kafka.DescribeClusterV2Output, error)
	listClustersV2    func(context.Context, *kafka.ListClustersV2Input, ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error)
	listNodes         func(context.Context, *kafka.ListNodesInput, ...func(*kafka.Options)) (*kafka.ListNodesOutput, error)
}

func newMSKClientAdapter(c *kafka.Client) mskClientAdapter {
	return mskClientAdapter{
		describeClusterV2: c.DescribeClusterV2,
		listClustersV2:    c.ListClustersV2,
		listNodes:         c.ListNodes,
	}
}

func (a mskClientAdapter) DescribeClusterV2(ctx context.Context, params *kafka.DescribeClusterV2Input, optFns ...func(*kafka.Options)) (*kafka.DescribeClusterV2Output, error) {
	return a.describeClusterV2(ctx, params, optFns...)
}

func (a mskClientAdapter) ListClustersV2(ctx context.Context, params *kafka.ListClustersV2Input, optFns ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	return a.listClustersV2(ctx, params, optFns...)
}

func (a mskClientAdapter) ListNodes(ctx context.Context, params *kafka.ListNodesInput, optFns ...func(*kafka.Options)) (*kafka.ListNodesOutput, error) {
	return a.listNodes(ctx, params, optFns...)
}

// newMSKDiscovery creates a new MSKDiscovery instance
func newMSKDiscovery(ctx context.Context, cfg aws.Config, d *Discovery) (*MSKDiscovery, error) {

	clientAdapter := newMSKClientAdapter(kafka.NewFromConfig(cfg, func(options *kafka.Options) {
		if d.cfg.Endpoint != "" {
			options.BaseEndpoint = &d.cfg.Endpoint
		}
		options.HTTPClient = cfg.HTTPClient
	}))

	// Test credentials by making a simple API call
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := clientAdapter.ListClustersV2(testCtx, &kafka.ListClustersV2Input{})
	if err != nil {
		return nil, fmt.Errorf("msk credential test failed: %w", err)
	}

	return &MSKDiscovery{
		Discovery: *d,
		msk:       clientAdapter,
	}, nil
}

// describeClusters describes the clusters with the given ARNs and returns their details.
func (d *MSKDiscovery) describeClusters(ctx context.Context, clusterARNs []string) ([]types.Cluster, error) {
	var (
		clusters []types.Cluster
		mu       sync.Mutex
	)
	errg, ectx := errgroup.WithContext(ctx)
	errg.SetLimit(d.cfg.RequestConcurrency)
	for _, clusterARN := range clusterARNs {
		errg.Go(func() error {
			cluster, err := d.msk.DescribeClusterV2(ectx, &kafka.DescribeClusterV2Input{
				ClusterArn: aws.String(clusterARN),
			})
			if err != nil {
				return fmt.Errorf("could not describe cluster %v: %w", clusterARN, err)
			}
			// The API may answer without any cluster information, which leaves
			// nothing to build targets from.
			if cluster.ClusterInfo == nil {
				d.logger.Warn("Skipping MSK cluster described without cluster information", "cluster", clusterARN)
				return nil
			}
			// Only provisioned clusters expose broker nodes; skip anything
			// else (e.g. serverless clusters) that was explicitly configured.
			if cluster.ClusterInfo.ClusterType != types.ClusterTypeProvisioned {
				d.logger.Warn("Skipping non-provisioned MSK cluster, only provisioned clusters are supported", "cluster", clusterARN, "type", string(cluster.ClusterInfo.ClusterType))
				return nil
			}
			mu.Lock()
			clusters = append(clusters, *cluster.ClusterInfo)
			mu.Unlock()
			return nil
		})
	}

	return clusters, errg.Wait()
}

// listClusters lists all MSK clusters in the configured region and returns their details.
func (d *MSKDiscovery) listClusters(ctx context.Context) ([]types.Cluster, error) {
	var (
		clusters  []types.Cluster
		nextToken *string
	)
	for {
		listClustersInput := kafka.ListClustersV2Input{
			ClusterTypeFilter: aws.String("PROVISIONED"),
			MaxResults:        aws.Int32(100),
			NextToken:         nextToken,
		}

		resp, err := d.msk.ListClustersV2(ctx, &listClustersInput)
		if err != nil {
			return nil, fmt.Errorf("could not list clusters: %w", err)
		}

		clusters = append(clusters, resp.ClusterInfoList...)
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return clusters, nil
}

// listNodes lists all nodes for the given clusters and returns a map of cluster ARN to its nodes.
func (d *MSKDiscovery) listNodes(ctx context.Context, clusters []types.Cluster) (map[string][]types.NodeInfo, error) {
	clusterNodeMap := make(map[string][]types.NodeInfo)
	mu := sync.Mutex{}
	errg, ectx := errgroup.WithContext(ctx)
	errg.SetLimit(d.cfg.RequestConcurrency)
	for _, cluster := range clusters {
		clusterARN := aws.ToString(cluster.ClusterArn)
		errg.Go(func() error {
			var clusterNodes []types.NodeInfo
			var nextToken *string
			for {
				resp, err := d.msk.ListNodes(ectx, &kafka.ListNodesInput{
					ClusterArn: aws.String(clusterARN),
					MaxResults: aws.Int32(100),
					NextToken:  nextToken,
				})
				if err != nil {
					return fmt.Errorf("could not list nodes for cluster %v: %w", clusterARN, err)
				}

				clusterNodes = append(clusterNodes, resp.NodeInfoList...)
				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}

			mu.Lock()
			clusterNodeMap[clusterARN] = clusterNodes
			mu.Unlock()
			return nil
		})
	}

	return clusterNodeMap, errg.Wait()
}

func (d *MSKDiscovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {

	var err error

	tg := &targetgroup.Group{
		Source: d.region,
	}

	var clusters []types.Cluster
	if len(d.cfg.Clusters) > 0 {
		clusters, err = d.describeClusters(ctx, d.cfg.Clusters)
		if err != nil {
			return nil, err
		}
	} else {
		clusters, err = d.listClusters(ctx)
		if err != nil {
			return nil, err
		}
	}

	clusterNodeMap, err := d.listNodes(ctx, clusters)
	if err != nil {
		return nil, err
	}

	var (
		targetsMu sync.Mutex
		wg        sync.WaitGroup
	)
	for _, cluster := range clusters {
		wg.Add(1)

		go func(cluster types.Cluster, nodes []types.NodeInfo) {
			defer wg.Done()

			// The provisioned configuration carries the broker software and
			// monitoring details, and the API omits it for clusters it does
			// not report as provisioned.
			var (
				brokerSoftware *types.BrokerSoftwareInfo
				openMonitoring *types.OpenMonitoringInfo
			)
			if p := cluster.Provisioned; p != nil {
				brokerSoftware = p.CurrentBrokerSoftwareInfo
				openMonitoring = p.OpenMonitoring
			}

			for _, node := range nodes {
				labels := model.LabelSet{
					mskLabelClusterName:      model.LabelValue(aws.ToString(cluster.ClusterName)),
					mskLabelClusterARN:       model.LabelValue(aws.ToString(cluster.ClusterArn)),
					mskLabelClusterState:     model.LabelValue(string(cluster.State)),
					mskLabelClusterType:      model.LabelValue(string(cluster.ClusterType)),
					mskLabelClusterVersion:   model.LabelValue(aws.ToString(cluster.CurrentVersion)),
					mskLabelNodeARN:          model.LabelValue(aws.ToString(node.NodeARN)),
					mskLabelNodeAddedTime:    model.LabelValue(aws.ToString(node.AddedToClusterTime)),
					mskLabelNodeInstanceType: model.LabelValue(aws.ToString(node.InstanceType)),
				}

				// The broker software labels are omitted when the API did not
				// report the software running on the cluster.
				if brokerSoftware != nil {
					labels[mskLabelClusterKafkaVersion] = model.LabelValue(aws.ToString(brokerSoftware.KafkaVersion))

					// The configuration ARN and revision labels are omitted when the cluster is not using a custom configuration.
					if brokerSoftware.ConfigurationArn != nil {
						labels[mskLabelClusterConfigurationARN] = model.LabelValue(aws.ToString(brokerSoftware.ConfigurationArn))
					}
					if brokerSoftware.ConfigurationRevision != nil {
						labels[mskLabelClusterConfigurationRevision] = model.LabelValue(strconv.FormatInt(aws.ToInt64(brokerSoftware.ConfigurationRevision), 10))
					}
				}

				// The JMX exporter label is omitted when Open Monitoring is
				// not enabled on the cluster.
				if om := openMonitoring; om != nil && om.Prometheus != nil && om.Prometheus.JmxExporter != nil {
					labels[mskLabelClusterJmxExporterEnabled] = model.LabelValue(strconv.FormatBool(aws.ToBool(om.Prometheus.JmxExporter.EnabledInBroker)))
				}

				for key, value := range cluster.Tags {
					labels[model.LabelName(mskLabelClusterTags+strutil.SanitizeLabelName(key))] = model.LabelValue(value)
				}

				switch nodeType(node) {
				case NodeTypeBroker:
					labels[mskLabelNodeType] = model.LabelValue(NodeTypeBroker)
					labels[mskLabelNodeAttachedENI] = model.LabelValue(aws.ToString(node.BrokerNodeInfo.AttachedENIId))
					labels[mskLabelBrokerID] = model.LabelValue(fmt.Sprintf("%.0f", aws.ToFloat64(node.BrokerNodeInfo.BrokerId)))
					labels[mskLabelBrokerClientSubnet] = model.LabelValue(aws.ToString(node.BrokerNodeInfo.ClientSubnet))
					labels[mskLabelBrokerClientVPCIP] = model.LabelValue(aws.ToString(node.BrokerNodeInfo.ClientVpcIpAddress))
					// The node exporter label is omitted when Open Monitoring
					// is not enabled on the cluster.
					if om := openMonitoring; om != nil && om.Prometheus != nil && om.Prometheus.NodeExporter != nil {
						labels[mskLabelBrokerNodeExporterEnabled] = model.LabelValue(strconv.FormatBool(aws.ToBool(om.Prometheus.NodeExporter.EnabledInBroker)))
					}

					for idx, endpoint := range node.BrokerNodeInfo.Endpoints {
						endpointLabels := labels.Clone()
						endpointLabels[mskLabelBrokerEndpointIndex] = model.LabelValue(strconv.Itoa(idx))
						endpointLabels[model.AddressLabel] = model.LabelValue(net.JoinHostPort(endpoint, strconv.Itoa(d.cfg.Port)))

						targetsMu.Lock()
						tg.Targets = append(tg.Targets, endpointLabels)
						targetsMu.Unlock()
					}

				case NodeTypeController:
					labels[mskLabelNodeType] = model.LabelValue(NodeTypeController)

					for idx, endpoint := range node.ControllerNodeInfo.Endpoints {
						endpointLabels := labels.Clone()
						endpointLabels[mskLabelControllerEndpointIndex] = model.LabelValue(strconv.Itoa(idx))
						endpointLabels[model.AddressLabel] = model.LabelValue(net.JoinHostPort(endpoint, strconv.Itoa(d.cfg.Port)))

						targetsMu.Lock()
						tg.Targets = append(tg.Targets, endpointLabels)
						targetsMu.Unlock()
					}
				default:
					continue
				}
			}
		}(cluster, clusterNodeMap[aws.ToString(cluster.ClusterArn)])
	}
	wg.Wait()

	return []*targetgroup.Group{tg}, nil
}

func nodeType(node types.NodeInfo) NodeType {
	if node.BrokerNodeInfo != nil {
		return NodeTypeBroker
	} else if node.ControllerNodeInfo != nil {
		return NodeTypeController
	}
	return ""
}
