package net_test

import (
	"github.com/cloudfoundry/bosh-agent/v2/platform/net"
	boshsettings "github.com/cloudfoundry/bosh-agent/v2/settings"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	fakesys "github.com/cloudfoundry/bosh-utils/system/fakes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Azure Accelerated Networking Integration", func() {
	var (
		fs                            *fakesys.FakeFileSystem
		runner                        *fakesys.FakeCmdRunner
		logger                        boshlog.Logger
		interfaceDriverDetector       net.InterfaceDriverDetector
		interfaceSelector             net.InterfaceSelector
		interfaceConfigurationCreator net.InterfaceConfigurationCreator
	)

	BeforeEach(func() {
		fs = fakesys.NewFakeFileSystem()
		runner = fakesys.NewFakeCmdRunner()
		logger = boshlog.NewLogger(boshlog.LevelNone)

		interfaceDriverDetector = net.NewInterfaceDriverDetector(fs, runner, logger)
		interfaceSelector = net.NewSyntheticInterfaceSelector(interfaceDriverDetector, logger)
		interfaceConfigurationCreator = net.NewInterfaceConfigurationCreatorWithSelector(logger, interfaceSelector)
	})

	Describe("Azure accelerated networking scenario", func() {
		Context("when Azure VM has both synthetic and VF interfaces", func() {
			var (
				networks        boshsettings.Networks
				interfacesByMAC map[string]string
			)

			BeforeEach(func() {
				// Setup network configuration (single DHCP network without specific MAC)
				networks = boshsettings.Networks{
					"default": boshsettings.Network{
						Type:    "dynamic",
						DNS:     []string{"8.8.8.8", "8.8.4.4"},
						Default: []string{"dns", "gateway"},
					},
				}

				// Setup Azure accelerated networking interfaces:
				// - eth0: synthetic interface (hv_netvsc driver) - this should be selected
				// - enP53091s1np0: VF interface (mlx5_core driver) - this should be ignored
				// In reality, both interfaces have the same MAC address in Azure accelerated networking,
				// but since MAC address detector returns a map, only one would be present.
				// The bosh-agent should prefer the synthetic interface.
				interfacesByMAC = map[string]string{
					"00:0d:3a:f5:76:bd": "eth0", // Only the synthetic interface is detected
				}

				// Setup synthetic interface
				fs.WriteFileString("/sys/class/net/eth0/address", "00:0d:3a:f5:76:bd")
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Stdout: `driver: hv_netvsc
version: 
firmware-version: 
expansion-rom-version: 
bus-info: 000d3af5-76bd-000d-3af5-76bd000d3af5
supports-statistics: yes
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no`,
				})

				// Setup VF interface (enP53091s1np0) if it were to be detected
				fs.WriteFileString("/sys/class/net/enP53091s1np0/address", "00:0d:3a:f5:76:bd")
				runner.AddCmdResult("ethtool -i enP53091s1np0", fakesys.FakeCmdResult{
					Stdout: `driver: mlx5_core
version: 5.0-0
firmware-version: 14.25.8362
expansion-rom-version: 
bus-info: cf63:00:02.0
supports-statistics: yes
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no`,
				})
			})

			It("selects the synthetic interface for configuration", func() {
				staticConfigs, dhcpConfigs, err := interfaceConfigurationCreator.CreateInterfaceConfigurations(networks, interfacesByMAC)
				Expect(err).ToNot(HaveOccurred())

				// Should create DHCP configuration for the synthetic interface
				Expect(staticConfigs).To(BeEmpty())
				Expect(dhcpConfigs).To(HaveLen(1))

				dhcpConfig := dhcpConfigs[0]
				Expect(dhcpConfig.Name).To(Equal("eth0")) // Should select the synthetic interface
			})
		})

		Context("when there are multiple interfaces with different MACs", func() {
			var (
				networks        boshsettings.Networks
				interfacesByMAC map[string]string
			)

			BeforeEach(func() {
				networks = boshsettings.Networks{
					"default": boshsettings.Network{
						Type:    "dynamic",
						DNS:     []string{"8.8.8.8", "8.8.4.4"},
						Default: []string{"dns", "gateway"},
					},
				}

				// Multiple interfaces where one is synthetic
				interfacesByMAC = map[string]string{
					"aa:bb:cc:dd:ee:01": "enP53091s1np0", // VF interface (mlx5_core)
					"aa:bb:cc:dd:ee:02": "eth0",          // synthetic interface (hv_netvsc)
				}

				// Setup VF interface
				fs.WriteFileString("/sys/class/net/enP53091s1np0/address", "aa:bb:cc:dd:ee:01")
				runner.AddCmdResult("ethtool -i enP53091s1np0", fakesys.FakeCmdResult{
					Stdout: `driver: mlx5_core
version: 5.0-0
firmware-version: 14.25.8362`,
				})

				// Setup synthetic interface
				fs.WriteFileString("/sys/class/net/eth0/address", "aa:bb:cc:dd:ee:02")
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Stdout: `driver: hv_netvsc
version: 
firmware-version: `,
				})
			})

			It("prefers the synthetic interface over VF interfaces", func() {
				staticConfigs, dhcpConfigs, err := interfaceConfigurationCreator.CreateInterfaceConfigurations(networks, interfacesByMAC)
				Expect(err).ToNot(HaveOccurred())

				// Should create DHCP configuration for the synthetic interface
				Expect(staticConfigs).To(BeEmpty())
				Expect(dhcpConfigs).To(HaveLen(1))

				dhcpConfig := dhcpConfigs[0]
				Expect(dhcpConfig.Name).To(Equal("eth0")) // Should prefer synthetic over VF
			})
		})

		Context("when no synthetic interfaces are available", func() {
			var (
				networks        boshsettings.Networks
				interfacesByMAC map[string]string
			)

			BeforeEach(func() {
				networks = boshsettings.Networks{
					"default": boshsettings.Network{
						Type:    "dynamic",
						DNS:     []string{"8.8.8.8", "8.8.4.4"},
						Default: []string{"dns", "gateway"},
					},
				}

				// Only VF interface available
				interfacesByMAC = map[string]string{
					"aa:bb:cc:dd:ee:01": "enP53091s1np0", // VF interface (mlx5_core)
				}

				// Setup VF interface
				fs.WriteFileString("/sys/class/net/enP53091s1np0/address", "aa:bb:cc:dd:ee:01")
				runner.AddCmdResult("ethtool -i enP53091s1np0", fakesys.FakeCmdResult{
					Stdout: `driver: mlx5_core
version: 5.0-0
firmware-version: 14.25.8362`,
				})
			})

			It("falls back to using the available VF interface", func() {
				staticConfigs, dhcpConfigs, err := interfaceConfigurationCreator.CreateInterfaceConfigurations(networks, interfacesByMAC)
				Expect(err).ToNot(HaveOccurred())

				// Should create DHCP configuration for the VF interface as fallback
				Expect(staticConfigs).To(BeEmpty())
				Expect(dhcpConfigs).To(HaveLen(1))

				dhcpConfig := dhcpConfigs[0]
				Expect(dhcpConfig.Name).To(Equal("enP53091s1np0")) // Should use the available interface
			})
		})

		Context("when on a non-Azure environment (e.g., AWS with virtio)", func() {
			var (
				networks        boshsettings.Networks
				interfacesByMAC map[string]string
			)

			BeforeEach(func() {
				networks = boshsettings.Networks{
					"default": boshsettings.Network{
						Type:    "dynamic",
						DNS:     []string{"8.8.8.8", "8.8.4.4"},
						Default: []string{"dns", "gateway"},
					},
				}

				// AWS/KVM interface with virtio driver
				interfacesByMAC = map[string]string{
					"aa:bb:cc:dd:ee:01": "eth0", // virtio interface
				}

				// Setup virtio interface (common in AWS, KVM)
				fs.WriteFileString("/sys/class/net/eth0/address", "aa:bb:cc:dd:ee:01")
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Stdout: `driver: virtio_net
version: 1.0.0
firmware-version: `,
				})
			})

			It("recognizes virtio interfaces as synthetic and uses them", func() {
				staticConfigs, dhcpConfigs, err := interfaceConfigurationCreator.CreateInterfaceConfigurations(networks, interfacesByMAC)
				Expect(err).ToNot(HaveOccurred())

				// Should create DHCP configuration for the virtio interface
				Expect(staticConfigs).To(BeEmpty())
				Expect(dhcpConfigs).To(HaveLen(1))

				dhcpConfig := dhcpConfigs[0]
				Expect(dhcpConfig.Name).To(Equal("eth0"))
			})
		})
	})
})
