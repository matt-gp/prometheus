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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/prometheus/common/model"

	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/util/strutil"
)

const (
	ec2Label                     = model.MetaLabelPrefix + "ec2_"
	ec2LabelAMI                  = ec2Label + "ami"
	ec2LabelAZ                   = ec2Label + "availability_zone"
	ec2LabelAZID                 = ec2Label + "availability_zone_id"
	ec2LabelArch                 = ec2Label + "architecture"
	ec2LabelIPv6Addresses        = ec2Label + "ipv6_addresses"
	ec2LabelInstanceID           = ec2Label + "instance_id"
	ec2LabelInstanceLifecycle    = ec2Label + "instance_lifecycle"
	ec2LabelInstanceState        = ec2Label + "instance_state"
	ec2LabelInstanceType         = ec2Label + "instance_type"
	ec2LabelOwnerID              = ec2Label + "owner_id"
	ec2LabelPlatform             = ec2Label + "platform"
	ec2LabelDefaultIPv6Address   = ec2Label + "default_ipv6_address"
	ec2LabelPrimaryIPv6Addresses = ec2Label + "primary_ipv6_addresses"
	ec2LabelPrimarySubnetID      = ec2Label + "primary_subnet_id"
	ec2LabelPrivateDNS           = ec2Label + "private_dns_name"
	ec2LabelPrivateIP            = ec2Label + "private_ip"
	ec2LabelPublicDNS            = ec2Label + "public_dns_name"
	ec2LabelPublicIP             = ec2Label + "public_ip"
	ec2LabelRegion               = ec2Label + "region"
	ec2LabelSubnetID             = ec2Label + "subnet_id"
	ec2LabelTag                  = ec2Label + "tag_"
	ec2LabelVPCID                = ec2Label + "vpc_id"
	ec2LabelSeparator            = ","
)

// EC2Discovery is the AWS discovery implementation for EC2.
// It implements the awsRefresher interface, which allows it to refresh AWS targets for EC2.
type EC2Discovery struct {
	Discovery
	ec2      ec2ClientAdapter
	azToAZID map[string]string
}

var _ awsDiscovery = (*EC2Discovery)(nil)

// ec2ClientAdapter holds the EC2 API calls that AWS discovery actually uses as
// method-value closures over the concrete *ec2.Client.
//
// It exists purely to keep the binary small. The Go linker, once reflection
// (reflect.Value.Method/Call plus struct-field traversal, both reachable via
// the YAML/config machinery) is live, conservatively retains every exported
// method of any concrete type that is reachable through an interface — and a
// type stored as a field of an interface-boxed struct counts. *ec2.Client has
// ~470 operation methods; retaining all of them pulls in ~1,500 serializers and
// roughly 21 MB. By capturing only the needed methods as func values, the
// concrete *ec2.Client is hidden inside closure contexts (which reflection
// cannot traverse) and never appears as a field of a boxed type, so dead-code
// elimination drops the unused operations.
type ec2ClientAdapter struct {
	describeAvailabilityZones func(ctx context.Context, params *ec2.DescribeAvailabilityZonesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAvailabilityZonesOutput, error)
	describeInstances         func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	describeNetworkInterfaces func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// newEC2ClientAdapter wraps a concrete *ec2.Client, capturing only the API
// calls AWS discovery needs. See the ec2ClientAdapter doc comment for why.
func newEC2ClientAdapter(c *ec2.Client) ec2ClientAdapter {
	return ec2ClientAdapter{
		describeAvailabilityZones: c.DescribeAvailabilityZones,
		describeInstances:         c.DescribeInstances,
		describeNetworkInterfaces: c.DescribeNetworkInterfaces,
	}
}

func (a ec2ClientAdapter) DescribeAvailabilityZones(ctx context.Context, params *ec2.DescribeAvailabilityZonesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAvailabilityZonesOutput, error) {
	return a.describeAvailabilityZones(ctx, params, optFns...)
}

func (a ec2ClientAdapter) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return a.describeInstances(ctx, params, optFns...)
}

func (a ec2ClientAdapter) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return a.describeNetworkInterfaces(ctx, params, optFns...)
}

// newEC2Discovery creates a new EC2Discovery instance
func newEC2Discovery(ctx context.Context, cfg aws.Config, d *Discovery) (*EC2Discovery, error) {

	ec2ClientAdapter := newEC2ClientAdapter(ec2.NewFromConfig(cfg, func(options *ec2.Options) {
		if d.cfg.Endpoint != "" {
			options.BaseEndpoint = &d.cfg.Endpoint
		}
		options.HTTPClient = cfg.HTTPClient
	}))

	// Test credentials by making a simple API call
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := ec2ClientAdapter.DescribeAvailabilityZones(testCtx, &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return nil, fmt.Errorf("unable to describe availability zones: %w", err)
	}

	return &EC2Discovery{
		Discovery: *d,
		ec2:       ec2ClientAdapter,
	}, nil
}

func (d *EC2Discovery) refreshAZIDs(ctx context.Context) error {
	azs, err := d.ec2.DescribeAvailabilityZones(ctx, &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return err
	}
	if azs.AvailabilityZones == nil {
		d.azToAZID = make(map[string]string)
		return nil
	}
	d.azToAZID = make(map[string]string, len(azs.AvailabilityZones))
	for _, az := range azs.AvailabilityZones {
		if az.ZoneName == nil || az.ZoneId == nil {
			continue
		}
		d.azToAZID[*az.ZoneName] = *az.ZoneId
	}
	return nil
}

func (d *EC2Discovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {

	tg := &targetgroup.Group{
		Source: d.region,
	}

	var filters []ec2Types.Filter
	for _, f := range d.cfg.Filters {
		filters = append(filters, ec2Types.Filter{
			Name:   aws.String(f.Name),
			Values: f.Values,
		})
	}

	// Only refresh the AZ ID map if we have never been able to build one.
	// Prometheus requires a reload if AWS adds a new AZ to the region.
	if d.azToAZID == nil {
		if err := d.refreshAZIDs(ctx); err != nil {
			d.logger.Debug(
				"Unable to describe availability zones",
				"err", err,
			)
		}
	}

	input := &ec2.DescribeInstancesInput{Filters: filters}
	paginator := ec2.NewDescribeInstancesPaginator(d.ec2, input)

	for paginator.HasMorePages() {
		p, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("could not describe instances: %w", err)
		}

		for _, r := range p.Reservations {
			for _, inst := range r.Instances {
				defaultIPv6Addr, primaryIPv6Addrs, ipv6Addrs := getInstanceIPv6Addresses(&inst)

				if inst.PrivateIpAddress == nil && defaultIPv6Addr == nil {
					continue
				}

				// Every instance field below is optional in the EC2 API. Omit
				// the label when the field is absent rather than dereferencing
				// a nil pointer, which would panic and take down the whole
				// Prometheus process.
				labels := model.LabelSet{
					ec2LabelRegion: model.LabelValue(d.region),
				}

				if inst.InstanceId != nil {
					labels[ec2LabelInstanceID] = model.LabelValue(*inst.InstanceId)
				}

				if r.OwnerId != nil {
					labels[ec2LabelOwnerID] = model.LabelValue(*r.OwnerId)
				}

				if defaultIPv6Addr != nil {
					labels[ec2LabelDefaultIPv6Address] = model.LabelValue(*defaultIPv6Addr)
				}

				if inst.PrivateIpAddress != nil {
					labels[ec2LabelPrivateIP] = model.LabelValue(*inst.PrivateIpAddress)
					labels[model.AddressLabel] = model.LabelValue(net.JoinHostPort(*inst.PrivateIpAddress, strconv.Itoa(d.cfg.Port)))
				} else {
					labels[model.AddressLabel] = model.LabelValue(net.JoinHostPort(*defaultIPv6Addr, strconv.Itoa(d.cfg.Port)))
				}

				if inst.PrivateDnsName != nil {
					labels[ec2LabelPrivateDNS] = model.LabelValue(*inst.PrivateDnsName)
				}

				if inst.Platform != "" {
					labels[ec2LabelPlatform] = model.LabelValue(inst.Platform)
				}

				if inst.PublicIpAddress != nil {
					labels[ec2LabelPublicIP] = model.LabelValue(*inst.PublicIpAddress)
					if inst.PublicDnsName != nil {
						labels[ec2LabelPublicDNS] = model.LabelValue(*inst.PublicDnsName)
					}
				}

				if primaryIPv6Addrs != nil {
					labels[ec2LabelPrimaryIPv6Addresses] = model.LabelValue(
						ec2LabelSeparator +
							strings.Join(primaryIPv6Addrs, ec2LabelSeparator) +
							ec2LabelSeparator,
					)
				}

				if ipv6Addrs != nil {
					labels[ec2LabelIPv6Addresses] = model.LabelValue(
						ec2LabelSeparator +
							strings.Join(ipv6Addrs, ec2LabelSeparator) +
							ec2LabelSeparator,
					)
				}

				if inst.ImageId != nil {
					labels[ec2LabelAMI] = model.LabelValue(*inst.ImageId)
				}

				// The availability zone ID is looked up by zone name, so both
				// labels are omitted when the placement is absent.
				if inst.Placement != nil && inst.Placement.AvailabilityZone != nil {
					az := *inst.Placement.AvailabilityZone
					labels[ec2LabelAZ] = model.LabelValue(az)
					azID, ok := d.azToAZID[az]
					if !ok && d.azToAZID != nil {
						d.logger.Debug(
							"Availability zone ID not found",
							"az", az,
						)
					}
					labels[ec2LabelAZID] = model.LabelValue(azID)
				}

				if inst.State != nil {
					labels[ec2LabelInstanceState] = model.LabelValue(inst.State.Name)
				}
				labels[ec2LabelInstanceType] = model.LabelValue(inst.InstanceType)

				if inst.InstanceLifecycle != "" {
					labels[ec2LabelInstanceLifecycle] = model.LabelValue(inst.InstanceLifecycle)
				}

				if inst.Architecture != "" {
					labels[ec2LabelArch] = model.LabelValue(inst.Architecture)
				}

				if inst.VpcId != nil {
					labels[ec2LabelVPCID] = model.LabelValue(*inst.VpcId)
					if inst.SubnetId != nil {
						labels[ec2LabelPrimarySubnetID] = model.LabelValue(*inst.SubnetId)
					}

					var subnets []string
					subnetsMap := make(map[string]struct{})
					for _, eni := range inst.NetworkInterfaces {
						if eni.SubnetId == nil {
							continue
						}
						// Deduplicate VPC Subnet IDs maintaining the order of the subnets returned by EC2.
						if _, ok := subnetsMap[*eni.SubnetId]; !ok {
							subnetsMap[*eni.SubnetId] = struct{}{}
							subnets = append(subnets, *eni.SubnetId)
						}
					}
					labels[ec2LabelSubnetID] = model.LabelValue(
						ec2LabelSeparator +
							strings.Join(subnets, ec2LabelSeparator) +
							ec2LabelSeparator,
					)
				}

				for _, t := range inst.Tags {
					if t.Key == nil || t.Value == nil {
						continue
					}
					name := strutil.SanitizeLabelName(*t.Key)
					labels[ec2LabelTag+model.LabelName(name)] = model.LabelValue(*t.Value)
				}
				tg.Targets = append(tg.Targets, labels)
			}
		}
	}

	return []*targetgroup.Group{tg}, nil
}

func getInstanceIPv6Addresses(i *ec2Types.Instance) (*string, []string, []string) {
	var primaryIPv6Addrs []string
	var ipv6Addrs []string

	if i.VpcId != nil {
		for _, eni := range i.NetworkInterfaces {
			if eni.SubnetId == nil {
				continue
			}

			for _, ipv6addr := range eni.Ipv6Addresses {
				// Nothing identifies an address without a value, so skip the
				// entry rather than dereferencing nil.
				if ipv6addr.Ipv6Address == nil {
					continue
				}
				ipv6Addrs = append(ipv6Addrs, *ipv6addr.Ipv6Address)

				// IsPrimaryIpv6 is only populated once a primary IPv6 address
				// has been enabled on the interface, so an absent flag means
				// the address is not primary.
				if !aws.ToBool(ipv6addr.IsPrimaryIpv6) {
					continue
				}

				// The device index gives the position to record the primary
				// address at; without a usable one there is no slot for it.
				if eni.Attachment == nil || eni.Attachment.DeviceIndex == nil || *eni.Attachment.DeviceIndex < 0 {
					continue
				}

				// we might have to extend the slice with more than one element
				// that could leave empty strings in the list which is intentional
				// to keep the position/device index information
				for int32(len(primaryIPv6Addrs)) <= *eni.Attachment.DeviceIndex {
					primaryIPv6Addrs = append(primaryIPv6Addrs, "")
				}
				primaryIPv6Addrs[*eni.Attachment.DeviceIndex] = *ipv6addr.Ipv6Address
			}
		}

		// Find an IPv6 address we can use by default. Pick the first primary one if
		// there is any available, if not then pick the first non-primary address.
		for _, ipv6addr := range append(primaryIPv6Addrs, ipv6Addrs...) {
			if ipv6addr != "" {
				return &ipv6addr, primaryIPv6Addrs, ipv6Addrs
			}
		}
	}

	return nil, primaryIPv6Addrs, ipv6Addrs
}
