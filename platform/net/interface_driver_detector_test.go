package net_test

import (
	"errors"

	"github.com/cloudfoundry/bosh-agent/v2/platform/net"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	fakesys "github.com/cloudfoundry/bosh-utils/system/fakes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("InterfaceDriverDetector", func() {
	var (
		fs                      *fakesys.FakeFileSystem
		runner                  *fakesys.FakeCmdRunner
		logger                  boshlog.Logger
		interfaceDriverDetector net.InterfaceDriverDetector
	)

	BeforeEach(func() {
		fs = fakesys.NewFakeFileSystem()
		runner = fakesys.NewFakeCmdRunner()
		logger = boshlog.NewLogger(boshlog.LevelNone)
		interfaceDriverDetector = net.NewInterfaceDriverDetector(fs, runner, logger)
	})

	Describe("DetectInterfaceDriver", func() {
		Context("when ethtool command succeeds", func() {
			BeforeEach(func() {
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
			})

			It("returns the driver name from ethtool output", func() {
				driver, err := interfaceDriverDetector.DetectInterfaceDriver("eth0")
				Expect(err).ToNot(HaveOccurred())
				Expect(driver).To(Equal("hv_netvsc"))
			})
		})

		Context("when ethtool command fails but sysfs is available", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Error: errors.New("ethtool failed"),
				})
				err := fs.WriteFileString("/sys/class/net/eth0/device/driver", "")
				Expect(err).ToNot(HaveOccurred())
				// Create a symlink to simulate the driver path
				err = fs.Symlink("../../../drivers/net/hv_netvsc", "/sys/class/net/eth0/device/driver")
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns the driver name from sysfs", func() {
				driver, err := interfaceDriverDetector.DetectInterfaceDriver("eth0")
				Expect(err).ToNot(HaveOccurred())
				Expect(driver).To(Equal("hv_netvsc"))
			})
		})

		Context("when both ethtool and sysfs fail", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i veth0", fakesys.FakeCmdResult{
					Error: errors.New("ethtool failed"),
				})
				// Create interface directory but no device/driver symlink (for virtual interfaces)
				err := fs.WriteFileString("/sys/class/net/veth0/address", "aa:bb:cc:dd:ee:ff")
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns empty string without error", func() {
				driver, err := interfaceDriverDetector.DetectInterfaceDriver("veth0")
				Expect(err).ToNot(HaveOccurred())
				Expect(driver).To(Equal(""))
			})
		})
	})

	Describe("IsSyntheticInterface", func() {
		Context("when interface uses hv_netvsc driver", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Stdout: `driver: hv_netvsc
version: 
firmware-version: `,
				})
			})

			It("returns true", func() {
				isSynthetic, err := interfaceDriverDetector.IsSyntheticInterface("eth0")
				Expect(err).ToNot(HaveOccurred())
				Expect(isSynthetic).To(BeTrue())
			})
		})

		Context("when interface uses mlx5_core driver (VF interface)", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i enP53091s1np0", fakesys.FakeCmdResult{
					Stdout: `driver: mlx5_core
version: 5.0-0
firmware-version: 14.25.8362`,
				})
			})

			It("returns false", func() {
				isSynthetic, err := interfaceDriverDetector.IsSyntheticInterface("enP53091s1np0")
				Expect(err).ToNot(HaveOccurred())
				Expect(isSynthetic).To(BeFalse())
			})
		})

		Context("when interface uses xen-netfront driver", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Stdout: `driver: xen-netfront
version: 
firmware-version: `,
				})
			})

			It("returns true", func() {
				isSynthetic, err := interfaceDriverDetector.IsSyntheticInterface("eth0")
				Expect(err).ToNot(HaveOccurred())
				Expect(isSynthetic).To(BeTrue())
			})
		})

		Context("when interface uses virtio_net driver", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i eth0", fakesys.FakeCmdResult{
					Stdout: `driver: virtio_net
version: 1.0.0
firmware-version: `,
				})
			})

			It("returns true", func() {
				isSynthetic, err := interfaceDriverDetector.IsSyntheticInterface("eth0")
				Expect(err).ToNot(HaveOccurred())
				Expect(isSynthetic).To(BeTrue())
			})
		})

		Context("when driver detection fails", func() {
			BeforeEach(func() {
				runner.AddCmdResult("ethtool -i unknown", fakesys.FakeCmdResult{
					Error: errors.New("interface not found"),
				})
				// Interface doesn't exist in sysfs either
			})

			It("returns an error", func() {
				_, err := interfaceDriverDetector.IsSyntheticInterface("unknown")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("does not exist"))
			})
		})
	})
})
