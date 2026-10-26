//go:build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package ctrnetworking

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/containerd/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/containerd/nerdbox/internal/nwcfg"
)

// Connect sets up networking for the container with the given pid, based on
// the configuration found at configPath.
func Connect(ctx context.Context, bundleDirname string, pid int) (func() error, error) {
	config, err := loadConfig(filepath.Join(bundleDirname, nwcfg.Filename))
	if err != nil {
		return nil, err
	}
	if len(config.Networks) == 0 {
		return nil, nil
	}

	eg, ctx := errgroup.WithContext(ctx)
	for _, n := range config.Networks {
		eg.Go(func() error {
			nshCtr, err := netns.GetFromPid(pid)
			if err != nil {
				return fmt.Errorf("getting container netns: %w", err)
			}
			defer func() {
				if err := nshCtr.Close(); err != nil {
					log.G(ctx).WithError(err).Warn("Closing container netns")
				}
			}()
			nlhCtr, err := netlink.NewHandleAt(nshCtr)
			if err != nil {
				return fmt.Errorf("creating netlink handle in container netns: %w", err)
			}
			defer nlhCtr.Close()

			nc, err := makeNet(n)
			if err != nil {
				return err
			}

			if nc.ctrVethName == "" {
				nc.ctrVethName = "eth%d" // The kernel will pick a number.
			}
			ctrVeth, err := nc.addVeth(nlhCtr, nshCtr)
			if err != nil {
				return err
			}
			if err := nc.addAddrs(nlhCtr, ctrVeth); err != nil {
				return err
			}
			if err := addDefaultGw(nlhCtr, ctrVeth, n.DefaultGw4); err != nil {
				return err
			}
			if err := addDefaultGw(nlhCtr, ctrVeth, n.DefaultGw6); err != nil {
				return err
			}

			log.G(ctx).WithFields(log.Fields{
				"task":      pid,
				"bridge":    nc.bridgeName,
				"host_veth": nc.hostVethName,
				"ctr_veth":  nc.ctrVethName,
			}).Debug("Added veth")
			return nil
		})
	}
	return func() error { return eg.Wait() }, nil
}

func loadConfig(path string) (*nwcfg.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config nwcfg.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

type netConfig struct {
	bridgeName   string
	ctrMAC       net.HardwareAddr
	hostVethName string
	ctrVethName  string
	addrs        []netip.Prefix
}

func makeNet(n nwcfg.Network) (netConfig, error) {
	var ctrMAC net.HardwareAddr
	if n.MAC == "" {
		ctrMAC = generateRandomMAC()
	} else {
		var err error
		ctrMAC, err = net.ParseMAC(n.MAC)
		if err != nil {
			return netConfig{}, err
		}
	}

	// Each container repeats the setup, finishing any move an earlier one left undone.
	bridgeName := bridgeNameFromMAC(n.VmMAC)
	if err := addBridgeNetwork(n.VmMAC, bridgeName); err != nil {
		return netConfig{}, err
	}

	return netConfig{
		bridgeName:   bridgeName,
		ctrMAC:       ctrMAC,
		hostVethName: "ve-" + strings.ReplaceAll(ctrMAC.String(), ":", ""),
		ctrVethName:  n.IfName,
		addrs:        n.Addrs,
	}, nil
}

// addBridgeNetwork puts hostIf on its bridge, which takes hostIf's MAC,
// addresses and routes: a bridge port's own addresses lose neighbor resolution.
func addBridgeNetwork(vmMAC string, bridgeName string) error {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	hostIf, err := linkByMAC(nil, vmMAC)
	if err != nil {
		return fmt.Errorf("getting host link: %w", err)
	}
	if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{
		Name:         bridgeName,
		HardwareAddr: hostIf.Attrs().HardwareAddr,
	}}); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("adding bridge %s: %w", bridgeName, err)
	}
	if err := netlink.LinkSetMaster(hostIf, &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}); err != nil {
		return fmt.Errorf("connecting %s to bridge %s: %w", hostIf.Attrs().Name, bridgeName, err)
	}
	br, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return fmt.Errorf("looking up bridge device %s: %w", bridgeName, err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return fmt.Errorf("set bridge %s 'up': %w", bridgeName, err)
	}
	if err := moveAddrs(&netlink.Handle{}, hostIf, br); err != nil {
		return fmt.Errorf("moving %s's addresses to bridge %s: %w", hostIf.Attrs().Name, bridgeName, err)
	}
	return nil
}

// bridgeMu serializes bridge setup: containers on one VM card connect concurrently.
var bridgeMu sync.Mutex

// addrRouter is the part of a netlink handle that moves addresses and routes.
type addrRouter interface {
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrReplace(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	RouteReplace(route *netlink.Route) error
}

// moveAddrs moves from's global addresses, and its routes other than their
// prefix routes, to to. A move that fails partway is rolled back.
func moveAddrs(nlh addrRouter, from, to netlink.Link) (retErr error) {
	addrs, err := nlh.AddrList(from, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("listing addresses: %w", err)
	}
	addrs = slices.DeleteFunc(addrs, func(addr netlink.Addr) bool { return addr.Scope != unix.RT_SCOPE_UNIVERSE })
	routes, err := nlh.RouteList(from, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}
	routes = slices.DeleteFunc(routes, func(route netlink.Route) bool { return route.Protocol == unix.RTPROT_KERNEL })

	var undo []func() error
	defer func() {
		if retErr == nil {
			return
		}
		for _, step := range slices.Backward(undo) {
			if err := step(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("rolling back: %w", err))
			}
		}
	}()

	for _, addr := range addrs {
		moved := &netlink.Addr{IPNet: addr.IPNet, Flags: addr.Flags}
		if err := nlh.AddrReplace(to, moved); err != nil {
			return fmt.Errorf("adding %s: %w", addr.IPNet, err)
		}
		undo = append(undo, func() error { return nlh.AddrDel(to, moved) })
	}
	// Routes move before the addresses go: deleting the last IPv4 address flushes from's routes.
	for _, route := range routes {
		moved := route
		moved.LinkIndex = to.Attrs().Index
		if err := nlh.RouteReplace(&moved); err != nil {
			return fmt.Errorf("moving route %s: %w", route, err)
		}
		undo = append(undo, func() error { return nlh.RouteReplace(&route) })
	}
	for _, addr := range addrs {
		if err := nlh.AddrDel(from, &addr); err != nil {
			return fmt.Errorf("deleting %s: %w", addr.IPNet, err)
		}
		undo = append(undo, func() error { return nlh.AddrReplace(from, &addr) })
	}
	return nil
}

// bridgeNameFromMAC returns a bridge name derived from a MAC address.
func bridgeNameFromMAC(mac string) string {
	return "br-" + strings.ReplaceAll(mac, ":", "")
}

// addVeth adds a veth pair connecting the host bridge to the container netns
// and returns a netlink.Link representing the container's interface.
func (nc netConfig) addVeth(nlhCtr *netlink.Handle, nshCtr netns.NsHandle) (netlink.Link, error) {
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   nc.hostVethName,
			TxQLen: 0,
		},
		PeerName:         nc.ctrVethName,
		PeerNamespace:    netlink.NsFd(nshCtr),
		PeerHardwareAddr: nc.ctrMAC,
	}); err != nil {
		return nil, fmt.Errorf("adding veth: %w", err)
	}

	hostVeth, err := netlink.LinkByName(nc.hostVethName)
	if err != nil {
		return nil, fmt.Errorf("getting host veth %s: %w", nc.hostVethName, err)
	}
	ctrVeth, err := linkByMAC(nlhCtr, nc.ctrMAC.String())
	if err != nil {
		return nil, fmt.Errorf("lookup container %s / %s: %w", nc.ctrVethName, nc.ctrMAC, err)
	}

	if err := netlink.LinkSetMaster(hostVeth, &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: nc.bridgeName}},
	); err != nil {
		return nil, fmt.Errorf("connecting %s to %s: %w", nc.hostVethName, nc.bridgeName, err)
	}
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		return nil, fmt.Errorf("setting VM's %s 'up': %w", nc.hostVethName, err)
	}
	if err := nlhCtr.LinkSetUp(ctrVeth); err != nil {
		return nil, fmt.Errorf("setting container's %s 'up': %w", nc.ctrVethName, err)
	}
	return ctrVeth, nil
}

func (nc netConfig) addAddrs(nlhCtr *netlink.Handle, ctrVeth netlink.Link) error {
	for _, addr := range nc.addrs {
		ipn := &net.IPNet{
			IP:   addr.Addr().AsSlice(),
			Mask: net.CIDRMask(addr.Bits(), addr.Addr().BitLen()),
		}
		if err := nlhCtr.AddrAdd(ctrVeth, &netlink.Addr{
			IPNet: ipn,
			Flags: unix.IFA_F_NODAD,
		}); err != nil {
			return fmt.Errorf("adding %s to container's %s: %w", addr, nc.ctrVethName, err)
		}
	}
	return nil
}

func addDefaultGw(nlhCtr *netlink.Handle, ctrVeth netlink.Link, gw netip.Addr) error {
	if !gw.IsValid() {
		return nil
	}
	if err := nlhCtr.RouteAdd(&netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: ctrVeth.Attrs().Index,
		Gw:        gw.AsSlice(),
	}); err != nil {
		return fmt.Errorf("add default gw %s: %w", gw, err)
	}
	return nil
}

// From https://github.com/moby/moby/blob/7a720df61f0cc629c47f97198225477f5dffff28/daemon/libnetwork/netutils/utils.go#L39
func generateRandomMAC() net.HardwareAddr {
	hw := make(net.HardwareAddr, 6)
	rand.Read(hw)
	hw[0] &= 0xfe // Unicast: clear multicast bit
	hw[0] |= 0x02 // Locally administered: set local assignment bit
	return hw
}

func linkByMAC(nlh *netlink.Handle, mac string) (netlink.Link, error) {
	if nlh == nil {
		var err error
		nlh, err = netlink.NewHandle()
		if err != nil {
			return nil, fmt.Errorf("creating netlink handle: %w", err)
		}
		defer nlh.Close()
	}
	links, err := nlh.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	// The VM card's bridge carries the card's MAC, so it never matches.
	idx := slices.IndexFunc(links, func(link netlink.Link) bool {
		return link.Type() != "bridge" && link.Attrs().HardwareAddr.String() == mac
	})
	if idx == -1 {
		return nil, fmt.Errorf("interface with MAC %s not found", mac)
	}
	return links[idx], nil
}
