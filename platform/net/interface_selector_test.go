package net_test

import (
	"errors"

	"github.com/cloudfoundry/bosh-agent/v2/platform/net"
	"github.com/cloudfoundry/bosh-agent/v2/platform/net/netfakes"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SyntheticInterfaceSelector", func() {
	var (
		fakeDriverDetector *netfakes.FakeInterfaceDriverDetector
		logger             boshlog.Logger
		selector           net.InterfaceSelector
	)

	BeforeEach(func() {
		fakeDriverDetector = &netfakes.FakeInterfaceDriverDetector{}
		logger = boshlog.NewLogger(boshlog.LevelNone)
		selector = net.NewSyntheticInterfaceSelector(fakeDriverDetector, logger)
	})

	Describe("SelectInterface", func() {
		Context("when no interfaces are available", func() {
			It("returns an error", func() {
				_, _, err := selector.SelectInterface(map[string]string{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("No interfaces available"))
			})
		})

		Context("when only one interface is available", func() {
			It("returns that interface without checking if it's synthetic", func() {
				interfaces := map[string]string{
					"aa:bb:cc:dd:ee:ff": "eth0",
				}

				mac, ifaceName, err := selector.SelectInterface(interfaces)
				Expect(err).ToNot(HaveOccurred())
				Expect(mac).To(Equal("aa:bb:cc:dd:ee:ff"))
				Expect(ifaceName).To(Equal("eth0"))

				// Should not have called the driver detector
				Expect(fakeDriverDetector.IsSyntheticInterfaceCallCount()).To(Equal(0))
			})
		})

		Context("when multiple interfaces are available", func() {
			var interfaces map[string]string

			BeforeEach(func() {
				interfaces = map[string]string{
					"aa:bb:cc:dd:ee:ff": "eth0",          // synthetic
					"11:22:33:44:55:66": "enP53091s1np0", // VF interface
				}
			})

			Context("and one is synthetic", func() {
				BeforeEach(func() {
					fakeDriverDetector.IsSyntheticInterfaceStub = func(interfaceName string) (bool, error) {
						switch interfaceName {
						case "eth0":
							return true, nil
						case "enP53091s1np0":
							return false, nil
						default:
							return false, nil
						}
					}
				})

				It("returns the synthetic interface", func() {
					mac, ifaceName, err := selector.SelectInterface(interfaces)
					Expect(err).ToNot(HaveOccurred())
					Expect(mac).To(Equal("aa:bb:cc:dd:ee:ff"))
					Expect(ifaceName).To(Equal("eth0"))

					Expect(fakeDriverDetector.IsSyntheticInterfaceCallCount()).To(Equal(2))

					// Check that both interfaces were checked
					calledInterfaces := make([]string, 0)
					for i := 0; i < fakeDriverDetector.IsSyntheticInterfaceCallCount(); i++ {
						calledInterfaces = append(calledInterfaces, fakeDriverDetector.IsSyntheticInterfaceArgsForCall(i))
					}
					Expect(calledInterfaces).To(ContainElements("eth0", "enP53091s1np0"))
				})
			})

			Context("and none are synthetic", func() {
				BeforeEach(func() {
					fakeDriverDetector.IsSyntheticInterfaceReturns(false, nil)
				})

				It("returns any available interface", func() {
					mac, ifaceName, err := selector.SelectInterface(interfaces)
					Expect(err).ToNot(HaveOccurred())
					Expect(mac).To(BeElementOf([]string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}))
					Expect(ifaceName).To(BeElementOf([]string{"eth0", "enP53091s1np0"}))
				})
			})

			Context("and driver detection fails for some interfaces", func() {
				BeforeEach(func() {
					fakeDriverDetector.IsSyntheticInterfaceStub = func(interfaceName string) (bool, error) {
						switch interfaceName {
						case "eth0":
							return false, errors.New("driver detection failed")
						case "enP53091s1np0":
							return false, nil
						default:
							return false, nil
						}
					}
				})

				It("treats failed detection as non-synthetic and returns an interface", func() {
					mac, ifaceName, err := selector.SelectInterface(interfaces)
					Expect(err).ToNot(HaveOccurred())
					Expect(mac).To(BeElementOf([]string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}))
					Expect(ifaceName).To(BeElementOf([]string{"eth0", "enP53091s1np0"}))
				})
			})
		})

		Context("when all interfaces have multiple synthetic interfaces", func() {
			It("returns one of the synthetic interfaces", func() {
				interfaces := map[string]string{
					"aa:bb:cc:dd:ee:ff": "eth0",
					"11:22:33:44:55:66": "eth1",
				}
				fakeDriverDetector.IsSyntheticInterfaceReturns(true, nil)

				mac, ifaceName, err := selector.SelectInterface(interfaces)
				Expect(err).ToNot(HaveOccurred())
				Expect(mac).To(BeElementOf([]string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}))
				Expect(ifaceName).To(BeElementOf([]string{"eth0", "eth1"}))
			})
		})
	})
})
