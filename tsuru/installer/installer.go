// Copyright 2016 tsuru-client authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package installer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/docker/machine/drivers/amazonec2"
	"github.com/tsuru/tsuru-client/tsuru/installer/dm"
	"github.com/tsuru/tsuru/cmd"
	"github.com/tsuru/tsuru/iaas/dockermachine"
)

var (
	defaultInstallOpts = &InstallOpts{
		DockerMachineConfig: dm.DefaultDockerMachineConfig,
		ComponentsConfig:    NewInstallConfig(dm.DefaultDockerMachineConfig.Name),
		CoreHosts:           1,
		AppsHosts:           1,
		DedicatedAppsHosts:  false,
		CoreDriversOpts:     make(map[string][]interface{}),
	}
	errDriverNotSupportLB = errors.New("Driver not support load balancer creation.")
)

type InstallOpts struct {
	*dm.DockerMachineConfig
	*ComponentsConfig
	CoreHosts          int
	CoreDriversOpts    map[string][]interface{}
	AppsHosts          int
	DedicatedAppsHosts bool
	AppsDriversOpts    map[string][]interface{}
}

type Installer struct {
	outWriter          io.Writer
	errWriter          io.Writer
	machineProvisioner dm.MachineProvisioner
	components         []TsuruComponent
	bootstraper        Bootstraper
	clusterCreator     func([]*dockermachine.Machine) (ServiceCluster, error)
	LBAddr             string
}

func (i *Installer) Install(opts *InstallOpts) (*Installation, error) {
	fmt.Fprintf(i.outWriter, "Running pre-install checks...\n")
	if errChecks := preInstallChecks(opts); errChecks != nil {
		return nil, fmt.Errorf("pre-install checks failed: %s", errChecks)
	}
	opts.CoreDriversOpts[opts.DriverName+"-open-port"] = []interface{}{strconv.Itoa(defaultTsuruAPIPort)}
	coreMachines, err := i.ProvisionMachines(opts.CoreHosts, opts.CoreDriversOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to provision components machines: %s", err)
	}
	err = i.ProvisionLoadBalancer(opts.DriverName, coreMachines, opts.ComponentsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to provision load balancer: %s", err)
	}
	cluster, err := i.clusterCreator(coreMachines)
	if err != nil {
		return nil, fmt.Errorf("failed to setup swarm cluster: %s", err)
	}
	err = i.InstallComponents(cluster, opts.ComponentsConfig)
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("http://%s:%d", cluster.GetManager().Base.Address, defaultTsuruAPIPort)
	installMachines, err := i.BootstrapTsuru(opts, target, coreMachines)
	if err != nil {
		return nil, err
	}
	i.applyIPtablesRules(coreMachines)
	return &Installation{
		CoreCluster:     cluster,
		InstallMachines: installMachines,
		Components:      i.components,
	}, nil
}

func (i *Installer) InstallComponents(cluster ServiceCluster, opts *ComponentsConfig) error {
	for _, component := range i.components {
		fmt.Fprintf(i.outWriter, "Installing %s\n", component.DisplayName())
		errInstall := component.Install(cluster, opts)
		if errInstall != nil {
			return fmt.Errorf("error installing %s: %s", component.DisplayName(), errInstall)
		}
		fmt.Fprintf(i.outWriter, "%s successfully installed!\n", component.DisplayName())
		if c, ok := component.(ExposableComponent); ok {
			opts.ComponentAddress[component.Name()] = fmt.Sprintf("%s:%d", i.LBAddr, c.LBPort())
		}
	}
	return nil
}

func (i *Installer) BootstrapTsuru(opts *InstallOpts, target string, coreMachines []*dockermachine.Machine) ([]*dockermachine.Machine, error) {
	fmt.Fprintf(i.outWriter, "Bootstrapping Tsuru API...")
	registryAddr, registryPort := parseAddress(opts.ComponentsConfig.ComponentAddress["registry"], "5000")
	bootstrapOpts := BoostrapOptions{
		Login:        opts.ComponentsConfig.RootUserEmail,
		Password:     opts.ComponentsConfig.RootUserPassword,
		Target:       target,
		TargetName:   opts.ComponentsConfig.TargetName,
		RegistryAddr: fmt.Sprintf("%s:%s", registryAddr, registryPort),
		NodesParams:  opts.AppsDriversOpts,
	}
	var installMachines []*dockermachine.Machine
	if opts.DriverName == "virtualbox" {
		appsMachines, errProv := i.ProvisionPool(opts, coreMachines)
		if errProv != nil {
			return nil, errProv
		}
		machineIndex := make(map[string]*dockermachine.Machine)
		installMachines = append(coreMachines, appsMachines...)
		for _, m := range installMachines {
			machineIndex[m.Host.Name] = m
		}
		var uniqueMachines []*dockermachine.Machine
		for _, v := range machineIndex {
			uniqueMachines = append(uniqueMachines, v)
		}
		installMachines = uniqueMachines
		var nodesAddr []string
		for _, m := range appsMachines {
			nodesAddr = append(nodesAddr, dm.GetPrivateAddress(m))
		}
		bootstrapOpts.NodesToRegister = nodesAddr
	} else {
		installMachines = coreMachines
		if opts.DedicatedAppsHosts {
			bootstrapOpts.NodesToCreate = opts.AppsHosts
		} else {
			var nodesAddr []string
			for _, m := range coreMachines {
				nodesAddr = append(nodesAddr, dm.GetPrivateAddress(m))
			}
			if opts.AppsHosts > opts.CoreHosts {
				bootstrapOpts.NodesToCreate = opts.AppsHosts - opts.CoreHosts
				bootstrapOpts.NodesToRegister = nodesAddr
			} else {
				bootstrapOpts.NodesToRegister = nodesAddr[:opts.AppsHosts]
			}
		}
	}
	err := i.bootstraper.Bootstrap(bootstrapOpts)
	if err != nil {
		return installMachines, fmt.Errorf("Error bootstrapping tsuru: %s", err)
	}
	return installMachines, nil
}

func (i *Installer) applyIPtablesRules(machines []*dockermachine.Machine) {
	fmt.Fprintf(i.outWriter, "Applying iptables workaround for docker 1.12...\n")
	for _, m := range machines {
		_, err := m.Host.RunSSHCommand("PATH=$PATH:/usr/sbin/:/usr/local/sbin; sudo iptables -D DOCKER-ISOLATION -i docker_gwbridge -o docker0 -j DROP")
		if err != nil {
			fmt.Fprintf(i.errWriter, "Failed to apply iptables rule: %s. Maybe it is not needed anymore?\n", err)
		}
		_, err = m.Host.RunSSHCommand("PATH=$PATH:/usr/sbin/:/usr/local/sbin; sudo iptables -D DOCKER-ISOLATION -i docker0 -o docker_gwbridge -j DROP")
		if err != nil {
			fmt.Fprintf(i.errWriter, "Failed to apply iptables rule: %s. Maybe it is not needed anymore?\n", err)
		}
	}
}

func preInstallChecks(config *InstallOpts) error {
	exists, err := cmd.CheckIfTargetLabelExists(config.Name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("tsuru target \"%s\" already exists", config.Name)
	}
	return nil
}

func (i *Installer) ProvisionPool(config *InstallOpts, hosts []*dockermachine.Machine) ([]*dockermachine.Machine, error) {
	if config.DedicatedAppsHosts {
		return i.ProvisionMachines(config.AppsHosts, config.AppsDriversOpts)
	}
	if config.AppsHosts > len(hosts) {
		poolMachines, err := i.ProvisionMachines(config.AppsHosts-len(hosts), config.AppsDriversOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to provision pool hosts: %s", err)
		}
		return append(poolMachines, hosts...), nil
	}
	return hosts[:config.AppsHosts], nil
}

func (i *Installer) ProvisionMachines(numMachines int, configs map[string][]interface{}) ([]*dockermachine.Machine, error) {
	var machines []*dockermachine.Machine
	for j := 0; j < numMachines; j++ {
		opts := make(map[string]interface{})
		for k, v := range configs {
			idx := j % len(v)
			opts[k] = v[idx]
		}
		m, err := i.machineProvisioner.ProvisionMachine(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to provision machines: %s", err)
		}
		machines = append(machines, m)
	}
	return machines, nil
}

func (i *Installer) ProvisionLoadBalancer(driverName string, machines []*dockermachine.Machine, opts *ComponentsConfig) error {
	switch driverName {
	case "amazonec2":
		driver := machines[0].Base.CustomData
		if driver == nil {
			return errors.New("Host machine has no driver.")
		}
		dbyte, err := json.Marshal(driver)
		if err != nil {
			return err
		}
		var d amazonec2.Driver
		err = json.Unmarshal(dbyte, &d)
		if err != nil {
			return errors.New(fmt.Sprintf("driver %#v cannot be casted to amazonec2 driver. error: %v", driver, err))
		}
		lbName := "installer"
		conf := aws.NewConfig()
		credentials := credentials.NewStaticCredentials(d.AccessKey, d.SecretKey, d.SessionToken)
		conf = conf.WithCredentials(credentials)
		conf = conf.WithRegion(d.Region)
		session := session.New(conf)
		lb := elb.New(session)
		protocol := "HTTP"
		port := int64(5000)
		input := elb.CreateLoadBalancerInput{
			Listeners: []*elb.Listener{{
				InstanceProtocol: &protocol,
				InstancePort:     &port,
				LoadBalancerPort: &port,
				Protocol:         &protocol,
			}},
			LoadBalancerName: &lbName,
			SecurityGroups:   []*string{&d.SecurityGroupId},
			Subnets:          []*string{&d.SubnetId},
		}
		output, err := lb.CreateLoadBalancer(&input)
		if err != nil {
			return err
		}
		i.LBAddr = *output.DNSName
		instances := []*elb.Instance{}
		for _, m := range machines {
			driver := m.Base.CustomData
			if driver == nil {
				return errors.New("Host machine has no driver.")
			}
			dbyte, err := json.Marshal(driver)
			if err != nil {
				return err
			}
			var d amazonec2.Driver
			err = json.Unmarshal(dbyte, &d)
			if err != nil {
				return errors.New(fmt.Sprintf("driver %#v cannot be casted to amazonec2 driver. error: %v", driver, err))
			}
			instance := elb.Instance{InstanceId: &d.InstanceId}
			instances = append(instances, &instance)
		}
		registerInput := elb.RegisterInstancesWithLoadBalancerInput{
			LoadBalancerName: &lbName,
			Instances:        instances,
		}
		_, err = lb.RegisterInstancesWithLoadBalancer(&registerInput)
		if err != nil {
			return err
		}
		listeners := []*elb.Listener{}
		for _, component := range i.components {
			if c, ok := component.(ExposableComponent); ok {
				port := int64(c.LBPort())
				listener := elb.Listener{
					InstancePort:     &port,
					InstanceProtocol: &protocol,
					LoadBalancerPort: &port,
					Protocol:         &protocol,
				}
				listeners = append(listeners, &listener)
			}
		}
		lbInput := elb.CreateLoadBalancerListenersInput{
			Listeners:        listeners,
			LoadBalancerName: &lbName,
		}
		_, err = lb.CreateLoadBalancerListeners(&lbInput)
		if err != nil {
			return err
		}
		return nil
	default:
		return errDriverNotSupportLB
	}
}

type Installation struct {
	CoreCluster     ServiceCluster
	InstallMachines []*dockermachine.Machine
	Components      []TsuruComponent
}

func (i *Installation) Summary() string {
	summary := fmt.Sprintf(`--- Installation Overview ---
Core Hosts:
%s
Core Components:
%s`, i.buildClusterTable().String(), i.buildComponentsTable().String())
	return summary
}

func (i *Installation) buildClusterTable() *cmd.Table {
	t := cmd.NewTable()
	t.Headers = cmd.Row{"IP", "State", "Manager"}
	t.LineSeparator = true
	nodes, err := i.CoreCluster.ClusterInfo()
	if err != nil {
		t.AddRow(cmd.Row{fmt.Sprintf("failed to retrieve cluster info: %s", err)})
	}
	for _, n := range nodes {
		t.AddRow(cmd.Row{n.IP, n.State, strconv.FormatBool(n.Manager)})
	}
	return t
}

func (i *Installation) buildComponentsTable() *cmd.Table {
	t := cmd.NewTable()
	t.Headers = cmd.Row{"Component", "Ports", "Replicas"}
	t.LineSeparator = true
	for _, component := range i.Components {
		info, err := component.Status(i.CoreCluster)
		if err != nil {
			t.AddRow(cmd.Row{component.Name(), "?", fmt.Sprintf("%s", err)})
			continue
		}
		row := cmd.Row{component.Name(),
			strings.Join(info.Ports, ","),
			strconv.Itoa(info.Replicas),
		}
		t.AddRow(row)
	}
	return t
}
