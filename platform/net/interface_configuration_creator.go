package net

import (
	"net"

	bosherr "github.com/cloudfoundry/bosh-utils/errors"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshsys "github.com/cloudfoundry/bosh-utils/system"

	boshsettings "github.com/cloudfoundry/bosh-agent/v2/settings"
)

type VirtualInterface struct {
	Label   string
	Address string
}

type StaticInterfaceConfiguration struct {
	Name                string
	Address             string
	Netmask             string
	Network             string
	Broadcast           string
	IsDefaultForGateway bool
	Mac                 string
	Gateway             string
	PostUpRoutes        boshsettings.Routes
	VirtualInterfaces   []VirtualInterface
}

func (c StaticInterfaceConfiguration) Version6() string {
	if c.IsVersion6() {
		return "6"
	}
	return ""
}

func (c StaticInterfaceConfiguration) IsVersion6() bool {
	return len(c.Network) == 0 && len(c.Broadcast) == 0
}

func (c StaticInterfaceConfiguration) CIDR() (string, error) {
	return boshsettings.NetmaskToCIDR(c.Netmask, c.IsVersion6())
}

type StaticInterfaceConfigurations []StaticInterfaceConfiguration

func (configs StaticInterfaceConfigurations) Len() int {
	return len(configs)
}

func (configs StaticInterfaceConfigurations) Less(i, j int) bool {
	return configs[i].Name < configs[j].Name
}

func (configs StaticInterfaceConfigurations) Swap(i, j int) {
	configs[i], configs[j] = configs[j], configs[i]
}

func (configs StaticInterfaceConfigurations) HasVersion6() bool {
	for _, config := range configs {
		if config.IsVersion6() {
			return true
		}
	}
	return false
}

type DHCPInterfaceConfiguration struct {
	Name         string
	PostUpRoutes boshsettings.Routes
	Address      string
}

func (c DHCPInterfaceConfiguration) Version6() string {
	if c.IsVersion6() {
		return "6"
	}
	return ""
}

func (c DHCPInterfaceConfiguration) IsVersion6() bool {
	ip := net.ParseIP(c.Address)
	if ip == nil || ip.To4() != nil {
		return false
	}
	return true
}

type DHCPInterfaceConfigurations []DHCPInterfaceConfiguration

func (configs DHCPInterfaceConfigurations) Len() int {
	return len(configs)
}

func (configs DHCPInterfaceConfigurations) Less(i, j int) bool {
	return configs[i].Name < configs[j].Name
}

func (configs DHCPInterfaceConfigurations) Swap(i, j int) {
	configs[i], configs[j] = configs[j], configs[i]
}

func (configs DHCPInterfaceConfigurations) HasVersion6() bool {
	for _, config := range configs {
		if len(config.Version6()) > 0 {
			return true
		}
	}
	return false
}

type InterfaceConfigurationCreator interface {
	CreateInterfaceConfigurations(boshsettings.Networks, map[string]string) ([]StaticInterfaceConfiguration, []DHCPInterfaceConfiguration, error)
}

type interfaceConfigurationCreator struct {
	logger            boshlog.Logger
	logTag            string
	interfaceSelector InterfaceSelector
}

func NewInterfaceConfigurationCreator(logger boshlog.Logger) InterfaceConfigurationCreator {
	// For backward compatibility, we'll create a default interface selector here
	// The actual platform managers can inject their own selector if needed
	return NewInterfaceConfigurationCreatorWithSelector(logger, nil)
}

func NewInterfaceConfigurationCreatorWithSelector(logger boshlog.Logger, selector InterfaceSelector) InterfaceConfigurationCreator {
	return interfaceConfigurationCreator{
		logger:            logger,
		logTag:            "interfaceConfigurationCreator",
		interfaceSelector: selector,
	}
}

func (creator interfaceConfigurationCreator) CreateInterfaceConfigurations(networks boshsettings.Networks, interfacesByMAC map[string]string) ([]StaticInterfaceConfiguration, []DHCPInterfaceConfiguration, error) {
	// In cases where we only have one network and it has no MAC address (either because the IAAS doesn't give us one or
	// it's an old CPI), if we only have one interface, we should map them
	if len(networks) == 1 && len(interfacesByMAC) == 1 {
		networkSettings := creator.getFirstNetwork(networks)
		if networkSettings.Mac == "" {
			var ifaceName string
			networkSettings.Mac, ifaceName = creator.getFirstInterface(interfacesByMAC)
			return creator.createInterfaceConfiguration([]StaticInterfaceConfiguration{}, []DHCPInterfaceConfiguration{}, ifaceName, networkSettings)
		}
	}

	return creator.createMultipleInterfaceConfigurations(networks, interfacesByMAC)
}

func (creator interfaceConfigurationCreator) createMultipleInterfaceConfigurations(networks boshsettings.Networks, interfacesByMAC map[string]string) ([]StaticInterfaceConfiguration, []DHCPInterfaceConfiguration, error) {
	// Validate potential MAC values on networks exist on host
	for name := range networks {
		if mac := networks[name].Mac; mac != "" {
			if _, ok := interfacesByMAC[mac]; !ok {
				return nil, nil, bosherr.Errorf("No device found for network '%s' with MAC address '%s'", name, mac)
			}
		}
	}

	// Configure interfaces with network settings matching MAC address.
	var networkSettings boshsettings.Network
	var err error
	staticConfigs := []StaticInterfaceConfiguration{}
	dhcpConfigs := []DHCPInterfaceConfiguration{}

	// Collect networks without specific MACs for later processing
	networksWithoutMAC := boshsettings.Networks{}
	for networkName, network := range networks {
		if network.Mac == "" && network.Alias == "" {
			networksWithoutMAC[networkName] = network
		}
	}

	// create interface configuration for networks that have a MAC specified
	for mac, ifaceName := range interfacesByMAC {
		networksSettings := networks.NetworksForMac(mac)

		// Only process if there are actual networks with this MAC (not the default empty one)
		if len(networksSettings) == 1 && networksSettings[0].Mac == "" && networksSettings[0].Type == "" {
			// This is the default empty network returned by NetworksForMac when no match is found
			// Skip it - we'll handle unmatched interfaces below
			continue
		}

		for _, networkSettings = range networksSettings {
			staticConfigs, dhcpConfigs, err = creator.createInterfaceConfiguration(staticConfigs, dhcpConfigs, ifaceName, networkSettings)
			if err != nil {
				return nil, nil, bosherr.WrapError(err, "Creating interface configuration")
			}
		}
	}

	// Handle networks without specific MACs - use interface selector if available
	if len(networksWithoutMAC) > 0 {
		// Get unassigned interfaces (not already configured above)
		unassignedInterfaces := make(map[string]string)
		for mac, ifaceName := range interfacesByMAC {
			// Check if this interface was already assigned to a network with specific MAC
			networksSettings := networks.NetworksForMac(mac)
			hasSpecificNetwork := false
			for _, net := range networksSettings {
				if net.Mac == mac {
					hasSpecificNetwork = true
					break
				}
			}
			if !hasSpecificNetwork {
				unassignedInterfaces[mac] = ifaceName
			}
		}

		// For each network without MAC, select the best interface if available
		networksWithoutMACList := make([]boshsettings.Network, 0, len(networksWithoutMAC))
		for _, network := range networksWithoutMAC {
			networksWithoutMACList = append(networksWithoutMACList, network)
		}

		for range networksWithoutMACList {
			if len(unassignedInterfaces) == 0 {
				// No more unassigned interfaces available - skip remaining networks without MAC
				creator.logger.Debug(creator.logTag, "No available interfaces for remaining networks without specific MAC addresses")
				break
			}

			var selectedMAC, selectedInterface string
			if creator.interfaceSelector != nil {
				selectedMAC, selectedInterface, err = creator.interfaceSelector.SelectInterface(unassignedInterfaces)
				if err != nil {
					creator.logger.Debug(creator.logTag, "Interface selector failed: %s, falling back to first available", err.Error())
					// Fallback to first available
					for mac, ifaceName := range unassignedInterfaces {
						selectedMAC, selectedInterface = mac, ifaceName
						break
					}
				}
			} else {
				// No selector, use first available
				for mac, ifaceName := range unassignedInterfaces {
					selectedMAC, selectedInterface = mac, ifaceName
					break
				}
			}

			// Remove selected interface from unassigned list
			delete(unassignedInterfaces, selectedMAC)

			// For networks without MAC, always create DHCP configuration
			// The lack of MAC indicates that specific interface assignment is not required
			dhcpConfigs = append(dhcpConfigs, DHCPInterfaceConfiguration{
				Name: selectedInterface,
			})
		}
	}

	// create interface configuration for networks that have an alias
	for _, networkSettings = range networks {
		if networkSettings.Mac != "" || networkSettings.Alias == "" {
			continue
		}

		staticConfigs, dhcpConfigs, err = creator.createInterfaceConfiguration(staticConfigs, dhcpConfigs, networkSettings.Alias, networkSettings)
		if err != nil {
			return nil, nil, bosherr.WrapError(err, "Creating interface configuration using alias")
		}
	}

	return staticConfigs, dhcpConfigs, nil
}

func (creator interfaceConfigurationCreator) createInterfaceConfiguration(staticConfigs []StaticInterfaceConfiguration, dhcpConfigs []DHCPInterfaceConfiguration, ifaceName string, networkSettings boshsettings.Network) ([]StaticInterfaceConfiguration, []DHCPInterfaceConfiguration, error) {
	creator.logger.Debug(creator.logTag, "Creating network configuration with settings: %s", networkSettings)

	if (networkSettings.IsDHCP() || networkSettings.Mac == "") && networkSettings.Alias == "" {
		creator.logger.Debug(creator.logTag, "Using dhcp networking")
		dhcpConfigs = append(dhcpConfigs, DHCPInterfaceConfiguration{
			Name:         ifaceName,
			PostUpRoutes: networkSettings.Routes,
			Address:      networkSettings.IP,
		})
	} else {
		creator.logger.Debug(creator.logTag, "Using static networking")
		networkAddress, broadcastAddress, _, err := boshsys.CalculateNetworkAndBroadcast(networkSettings.IP, networkSettings.Netmask)
		if err != nil {
			return nil, nil, bosherr.WrapError(err, "Calculating Network and Broadcast")
		}

		staticConfigs = append(staticConfigs, StaticInterfaceConfiguration{
			Name:                ifaceName,
			Address:             networkSettings.IP,
			Netmask:             networkSettings.Netmask,
			Network:             networkAddress,
			IsDefaultForGateway: networkSettings.IsDefaultFor("gateway"),
			Broadcast:           broadcastAddress,
			Mac:                 networkSettings.Mac,
			Gateway:             networkSettings.Gateway,
			PostUpRoutes:        networkSettings.Routes,
		})
	}
	return staticConfigs, dhcpConfigs, nil
}

func (creator interfaceConfigurationCreator) getFirstNetwork(networks boshsettings.Networks) boshsettings.Network {
	for networkName := range networks {
		return networks[networkName]
	}
	return boshsettings.Network{}
}

func (creator interfaceConfigurationCreator) getFirstInterface(interfacesByMAC map[string]string) (string, string) {
	// If we have an interface selector, use it to choose the best interface
	if creator.interfaceSelector != nil {
		mac, ifaceName, err := creator.interfaceSelector.SelectInterface(interfacesByMAC)
		if err != nil {
			creator.logger.Debug(creator.logTag, "Interface selector failed: %s, falling back to default selection", err.Error())
		} else {
			return mac, ifaceName
		}
	}

	// Fallback to original behavior: return first interface found
	for mac := range interfacesByMAC {
		return mac, interfacesByMAC[mac]
	}
	return "", ""
}
