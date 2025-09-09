package net

import (
	"encoding/json"
	gonet "net"
	"path"
	"strings"

	bosherr "github.com/cloudfoundry/bosh-utils/errors"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshsys "github.com/cloudfoundry/bosh-utils/system"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . MACAddressDetector

type MACAddressDetector interface {
	DetectMacAddresses() (map[string]string, error)
}

const (
	ifaliasPrefix = "bosh-interface"
)

type linuxMacAddressDetector struct {
	fs     boshsys.FileSystem
	logger boshlog.Logger
}

type windowsMacAddressDetector struct {
	interfacesFunction func() ([]gonet.Interface, error)
	runner             boshsys.CmdRunner
	logger             boshlog.Logger
}

type netAdapter struct {
	Name       string
	MacAddress string
}

func NewLinuxMacAddressDetector(fs boshsys.FileSystem, logger boshlog.Logger) MACAddressDetector {
	return linuxMacAddressDetector{
		fs:     fs,
		logger: logger,
	}
}

func NewWindowsMacAddressDetector(runner boshsys.CmdRunner, interfacesFunction func() ([]gonet.Interface, error), logger boshlog.Logger) MACAddressDetector {
	return windowsMacAddressDetector{
		interfacesFunction: interfacesFunction,
		runner:             runner,
		logger:             logger,
	}
}

func (d linuxMacAddressDetector) DetectMacAddresses() (map[string]string, error) {
	addresses := map[string]string{}

	filePaths, err := d.fs.Glob("/sys/class/net/*")
	if err != nil {
		return addresses, bosherr.WrapError(err, "Getting file list from /sys/class/net")
	}

	var macAddress string
	var ifalias string
	for _, filePath := range filePaths {
		d.logger.Debug("linuxMacAddressDetector", "Processing file %s", filePath)

		isPhysicalDevice := d.fs.FileExists(path.Join(filePath, "device"))

		// For third-party networking plugin case that the physical interface is used as bridge
		// interface and a virtual interface is created to replace it, the virtual interface needs
		// to be included in the detected result.
		// The virtual interface has an ifalias that has the prefix "bosh-interface"
		hasBoshPrefix := false
		ifalias, err = d.fs.ReadFileString(path.Join(filePath, "ifalias"))
		if err == nil {
			hasBoshPrefix = strings.HasPrefix(ifalias, ifaliasPrefix)
		}

		if isPhysicalDevice || hasBoshPrefix {
			macAddress, err = d.fs.ReadFileString(path.Join(filePath, "address"))
			if err != nil {
				return addresses, bosherr.WrapError(err, "Reading mac address from file")
			}

			macAddress = strings.Trim(macAddress, "\n")
			interfaceName := path.Base(filePath)

			// Check if the interface is synthetic by checking if the master directory exists
			// SR-IOV Interfaces have the same MAC address as the physical interface
			// and should not be used by the application.
			masterPath := path.Join(filePath, "master")
			if d.fs.FileExists(masterPath) {
				info, err := d.fs.Stat(masterPath)
				if err == nil && info.IsDir() {
					d.logger.Debug("linuxMacAddressDetector", "Skipping VF interface %s (%s)", interfaceName, filePath)
					continue
				}
			}

			if _, ok := addresses[macAddress]; ok {
				d.logger.Warn("linuxMacAddressDetector", "Detected duplicate MAC address '%s' for interfaces '%s' and '%s'", macAddress, addresses[macAddress], interfaceName)
			}

			addresses[macAddress] = interfaceName
		}
	}

	d.logger.Debug("linuxMacAddressDetector", "Detected MAC addresses: %v", addresses)
	return addresses, nil
}

func (d windowsMacAddressDetector) DetectMacAddresses() (map[string]string, error) {
	ifs, err := d.interfacesFunction()
	if err != nil {
		return nil, bosherr.WrapError(err, "Detecting Mac Addresses")
	}
	macs := make(map[string]string, len(ifs))

	var netAdapters []netAdapter
	stdout, stderr, _, err := d.runner.RunCommand("powershell", "-Command", "Get-NetAdapter | Select MacAddress,Name | ConvertTo-Json")
	if err != nil {
		return nil, bosherr.WrapErrorf(err, "Getting visible adapters: %s", stderr)
	}

	err = json.Unmarshal([]byte(stdout), &netAdapters)
	if err != nil {
		var singularNetAdapter netAdapter
		err = json.Unmarshal([]byte(stdout), &singularNetAdapter)
		if err != nil {
			return nil, bosherr.WrapError(err, "Parsing Get-NetAdapter output")
		}
		netAdapters = append(netAdapters, singularNetAdapter)
	}

	for _, f := range ifs {
		if adapterVisible(netAdapters, f.HardwareAddr.String(), f.Name) {
			macs[f.HardwareAddr.String()] = f.Name
		}
	}
	return macs, nil
}

func adapterVisible(netAdapters []netAdapter, macAddress string, adapterName string) bool {
	for _, adapter := range netAdapters {
		adapterMac, _ := gonet.ParseMAC(adapter.MacAddress) //nolint:errcheck
		if adapter.Name == adapterName && adapterMac.String() == macAddress {
			return true
		}
	}
	return false
}
