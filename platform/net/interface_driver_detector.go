package net

import (
	"path"
	"runtime"
	"slices"
	"strings"

	bosherr "github.com/cloudfoundry/bosh-utils/errors"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshsys "github.com/cloudfoundry/bosh-utils/system"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . InterfaceDriverDetector

type InterfaceDriverDetector interface {
	DetectInterfaceDriver(interfaceName string) (string, error)
	IsSyntheticInterface(interfaceName string) (bool, error)
}

type linuxInterfaceDriverDetector struct {
	fs     boshsys.FileSystem
	runner boshsys.CmdRunner
	logger boshlog.Logger
}

type windowsInterfaceDriverDetector struct {
	runner boshsys.CmdRunner
	logger boshlog.Logger
}

const logTag = "InterfaceDriverDetector"

func NewInterfaceDriverDetector(fs boshsys.FileSystem, runner boshsys.CmdRunner, logger boshlog.Logger) InterfaceDriverDetector {
	if runtime.GOOS == "windows" {
		return windowsInterfaceDriverDetector{
			runner: runner,
			logger: logger,
		}
	}
	return linuxInterfaceDriverDetector{
		fs:     fs,
		runner: runner,
		logger: logger,
	}
}

func (d linuxInterfaceDriverDetector) DetectInterfaceDriver(interfaceName string) (string, error) {
	// Try to get driver via ethtool first (most reliable)
	d.logger.Debug(logTag, "Trying to detect interface driver for %s", interfaceName)
	stdout, _, _, err := d.runner.RunCommand("ethtool", "-i", interfaceName)
	if err == nil {
		lines := strings.Split(stdout, "\n")
		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "driver:"); ok {
				driver := strings.TrimSpace(after)
				return driver, nil
			}
		}
	}

	// Check if interface exists in sysfs
	d.logger.Debug(logTag, "Checking if interface exists in sysfs for %s", interfaceName)
	interfacePath := path.Join("/sys/class/net", interfaceName)
	if !d.fs.FileExists(interfacePath) {
		return "", bosherr.Errorf("Interface '%s' does not exist", interfaceName)
	}

	// Fallback: read from sysfs
	d.logger.Debug(logTag, "Falling back to sysfs for %s", interfaceName)
	driverPath := path.Join("/sys/class/net", interfaceName, "device/driver")
	if d.fs.FileExists(driverPath) {
		realPath, err := d.fs.Readlink(driverPath)
		if err == nil {
			driver := path.Base(realPath)
			return driver, nil
		}
	}

	// If ethtool and sysfs fail, but interface exists, return empty string (not an error for virtual interfaces)
	d.logger.Debug(logTag, "Could not determine driver for interface '%s'", interfaceName)
	return "", nil
}

func (d linuxInterfaceDriverDetector) IsSyntheticInterface(interfaceName string) (bool, error) {
	driver, err := d.DetectInterfaceDriver(interfaceName)
	d.logger.Debug(logTag, "Driver for interface '%s': %s", interfaceName, driver)
	if err != nil {
		return false, err
	}

	// Azure synthetic interfaces use the hv_netvsc driver
	// Other cloud providers may have different synthetic drivers
	syntheticDrivers := []string{
		"hv_netvsc",    // Azure/Hyper-V synthetic network driver
		"xen-netfront", // Xen virtual network driver (used by some cloud providers)
		"virtio_net",   // KVM/QEMU virtual network driver
	}

	if slices.Contains(syntheticDrivers, driver) {
		d.logger.Debug(logTag, "Detected synthetic interface '%s' with driver '%s'", interfaceName, driver)
		return true, nil
	}

	d.logger.Debug(logTag, "Interface '%s' with driver '%s' is not synthetic", interfaceName, driver)
	return false, nil
}

func (d windowsInterfaceDriverDetector) DetectInterfaceDriver(interfaceName string) (string, error) {
	// On Windows, use Get-NetAdapter to get driver information
	stdout, stderr, _, err := d.runner.RunCommand("powershell", "-Command",
		"Get-NetAdapter -Name '"+interfaceName+"' | Select-Object DriverName | ConvertTo-Json")
	if err != nil {
		return "", bosherr.WrapErrorf(err, "Getting driver for interface %s: %s", interfaceName, stderr)
	}

	// Parse the JSON output to extract driver name
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if strings.Contains(line, "DriverName") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				driver := strings.Trim(strings.TrimSpace(parts[1]), `",`)
				return driver, nil
			}
		}
	}

	return "", nil
}

func (d windowsInterfaceDriverDetector) IsSyntheticInterface(interfaceName string) (bool, error) {
	driver, err := d.DetectInterfaceDriver(interfaceName)
	if err != nil {
		return false, err
	}

	// Windows Hyper-V synthetic network adapter drivers
	syntheticDrivers := []string{
		"netvsc",       // Windows Hyper-V synthetic network driver
		"vmnetadapter", // Some versions use this name
	}

	driverLower := strings.ToLower(driver)
	for _, syntheticDriver := range syntheticDrivers {
		if strings.Contains(driverLower, strings.ToLower(syntheticDriver)) {
			return true, nil
		}
	}

	return false, nil
}
