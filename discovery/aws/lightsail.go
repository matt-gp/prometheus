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
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/util/strutil"
)

const (
	lightsailLabel                    = model.MetaLabelPrefix + "lightsail_"
	lightsailLabelAZ                  = lightsailLabel + "availability_zone"
	lightsailLabelBlueprintID         = lightsailLabel + "blueprint_id"
	lightsailLabelBundleID            = lightsailLabel + "bundle_id"
	lightsailLabelInstanceName        = lightsailLabel + "instance_name"
	lightsailLabelInstanceState       = lightsailLabel + "instance_state"
	lightsailLabelInstanceSupportCode = lightsailLabel + "instance_support_code"
	lightsailLabelIPv6Addresses       = lightsailLabel + "ipv6_addresses"
	lightsailLabelPrivateIP           = lightsailLabel + "private_ip"
	lightsailLabelPublicIP            = lightsailLabel + "public_ip"
	lightsailLabelRegion              = lightsailLabel + "region"
	lightsailLabelTag                 = lightsailLabel + "tag_"
	lightsailLabelSeparator           = ","
)

// LightsailDiscovery is the AWS discovery implementation for Lightsail.
// It implements the awsRefresher interface, which allows it to refresh AWS targets for Lightsail.
type LightsailDiscovery struct {
	Discovery
	lightsail lightsailClientAdapter
}

var _ awsDiscovery = (*LightsailDiscovery)(nil)

// lightsailClientAdapter captures only the Lightsail API calls AWS discovery
// uses as method-value closures, keeping the concrete *lightsail.Client out of
// any interface-boxed struct field. See ec2ClientAdapter for the full
// rationale: this stops the linker from retaining the entire Lightsail API
// surface (~3.4 MB).
type lightsailClientAdapter struct {
	getInstances func(ctx context.Context, params *lightsail.GetInstancesInput, optFns ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error)
}

func newLightsailClientAdapter(c *lightsail.Client) lightsailClientAdapter {
	return lightsailClientAdapter{getInstances: c.GetInstances}
}

func (a lightsailClientAdapter) GetInstances(ctx context.Context, params *lightsail.GetInstancesInput, optFns ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error) {
	return a.getInstances(ctx, params, optFns...)
}

// newLightsailDiscovery creates a new LightsailDiscovery instance
func newLightsailDiscovery(ctx context.Context, cfg aws.Config, d *Discovery) (*LightsailDiscovery, error) {

	clientAdapter := newLightsailClientAdapter(lightsail.NewFromConfig(cfg, func(options *lightsail.Options) {
		if d.cfg.Endpoint != "" {
			options.BaseEndpoint = &d.cfg.Endpoint
		}
		options.HTTPClient = cfg.HTTPClient
	}))

	return &LightsailDiscovery{
		Discovery: *d,
		lightsail: clientAdapter,
	}, nil
}

func (d *LightsailDiscovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {

	tg := &targetgroup.Group{
		Source: d.region,
	}

	input := &lightsail.GetInstancesInput{}

	output, err := d.clientAdapter.GetInstances(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("could not get instances: %w", err)
	}

	for _, inst := range output.Instances {
		if inst.PrivateIpAddress == nil {
			continue
		}

		// Every field below is optional in the Lightsail API. Omit the label
		// when the field is absent rather than dereferencing a nil pointer,
		// which would panic and take down the whole Prometheus process.
		labels := model.LabelSet{
			lightsailLabelPrivateIP: model.LabelValue(*inst.PrivateIpAddress),
			lightsailLabelRegion:    model.LabelValue(d.region),
		}

		if inst.Location != nil && inst.Location.AvailabilityZone != nil {
			labels[lightsailLabelAZ] = model.LabelValue(*inst.Location.AvailabilityZone)
		}
		if inst.BlueprintId != nil {
			labels[lightsailLabelBlueprintID] = model.LabelValue(*inst.BlueprintId)
		}
		if inst.BundleId != nil {
			labels[lightsailLabelBundleID] = model.LabelValue(*inst.BundleId)
		}
		if inst.Name != nil {
			labels[lightsailLabelInstanceName] = model.LabelValue(*inst.Name)
		}
		if inst.State != nil && inst.State.Name != nil {
			labels[lightsailLabelInstanceState] = model.LabelValue(*inst.State.Name)
		}
		if inst.SupportCode != nil {
			labels[lightsailLabelInstanceSupportCode] = model.LabelValue(*inst.SupportCode)
		}

		addr := net.JoinHostPort(*inst.PrivateIpAddress, strconv.Itoa(d.cfg.Port))
		labels[model.AddressLabel] = model.LabelValue(addr)

		if inst.PublicIpAddress != nil {
			labels[lightsailLabelPublicIP] = model.LabelValue(*inst.PublicIpAddress)
		}

		if len(inst.Ipv6Addresses) > 0 {
			var ipv6addrs []string
			ipv6addrs = append(ipv6addrs, inst.Ipv6Addresses...)
			labels[lightsailLabelIPv6Addresses] = model.LabelValue(
				lightsailLabelSeparator +
					strings.Join(ipv6addrs, lightsailLabelSeparator) +
					lightsailLabelSeparator,
			)
		}

		for _, t := range inst.Tags {
			if t.Key == nil || t.Value == nil {
				continue
			}
			name := strutil.SanitizeLabelName(*t.Key)
			labels[lightsailLabelTag+model.LabelName(name)] = model.LabelValue(*t.Value)
		}

		tg.Targets = append(tg.Targets, labels)
	}
	return []*targetgroup.Group{tg}, nil
}
