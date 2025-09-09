package net

import (
	bosherr "github.com/cloudfoundry/bosh-utils/errors"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . InterfaceSelector

type InterfaceSelector interface {
	SelectInterface(interfacesByMAC map[string]string) (string, string, error)
}

type syntheticInterfaceSelector struct {
	driverDetector InterfaceDriverDetector
	logger         boshlog.Logger
	logTag         string
}

func NewSyntheticInterfaceSelector(driverDetector InterfaceDriverDetector, logger boshlog.Logger) InterfaceSelector {
	return syntheticInterfaceSelector{
		driverDetector: driverDetector,
		logger:         logger,
		logTag:         "syntheticInterfaceSelector",
	}
}

func (s syntheticInterfaceSelector) SelectInterface(interfacesByMAC map[string]string) (string, string, error) {
	if len(interfacesByMAC) == 0 {
		return "", "", bosherr.Error("No interfaces available")
	}

	// If only one interface, return it
	if len(interfacesByMAC) == 1 {
		for mac, ifaceName := range interfacesByMAC {
			return mac, ifaceName, nil
		}
	}

	// Look for synthetic interfaces first (preferred for Azure accelerated networking)
	s.logger.Debug(s.logTag, "Looking for synthetic interfaces in %d available interfaces", len(interfacesByMAC))
	syntheticInterfaces := make(map[string]string)
	otherInterfaces := make(map[string]string)

	for mac, ifaceName := range interfacesByMAC {
		isSynthetic, err := s.driverDetector.IsSyntheticInterface(ifaceName)
		if err != nil {
			s.logger.Debug(s.logTag, "Failed to determine if interface %s is synthetic: %s", ifaceName, err.Error())
			// If we can't determine, treat as non-synthetic
			otherInterfaces[mac] = ifaceName
			continue
		}

		if isSynthetic {
			s.logger.Debug(s.logTag, "Interface %s detected as synthetic", ifaceName)
			syntheticInterfaces[mac] = ifaceName
		} else {
			s.logger.Debug(s.logTag, "Interface %s detected as non-synthetic", ifaceName)
			otherInterfaces[mac] = ifaceName
		}
	}

	// Prefer synthetic interfaces (these handle the bonding on Azure)
	if len(syntheticInterfaces) > 0 {
		s.logger.Debug(s.logTag, "Selecting synthetic interface from %d available synthetic interfaces", len(syntheticInterfaces))
		for mac, ifaceName := range syntheticInterfaces {
			return mac, ifaceName, nil
		}
	}

	// Fallback to any other interface if no synthetic found
	if len(otherInterfaces) > 0 {
		s.logger.Debug(s.logTag, "No synthetic interfaces found, selecting from %d other interfaces", len(otherInterfaces))
		for mac, ifaceName := range otherInterfaces {
			return mac, ifaceName, nil
		}
	}

	return "", "", bosherr.Error("No suitable interface found")
}
