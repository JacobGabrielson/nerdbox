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
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/containerd/nerdbox/internal/nwcfg"
)

func TestAddBridgeNetworkMovesTheVMAddressToTheBridge(t *testing.T) {
	vmMAC, nic, gateway := newVM(t)
	require.NoError(t, addBridgeNetwork(vmMAC.String(), "br-test"))

	// A port with a lower MAC would become the bridge's MAC unless one was set.
	lowMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "ve-test", HardwareAddr: lowMAC}, PeerName: "ve-peer"}))
	port, err := netlink.LinkByName("ve-test")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetMaster(port, &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-test"}}))
	require.NoError(t, netlink.LinkSetUp(port))

	br, err := netlink.LinkByName("br-test")
	require.NoError(t, err)
	assert.Equal(t, vmMAC, br.Attrs().HardwareAddr)
	requireMoved(t, nic, br)

	conn, err := net.DialTimeout("tcp4", gateway, 5*time.Second)
	require.NoError(t, err, "reaching the gateway from the bridged VM address")
	_ = conn.Close()
}

func TestMoveAddrsRollsBackAFailedMove(t *testing.T) {
	for name, nlh := range map[string]func(nic netlink.Link) addrRouter{
		"route move":     func(netlink.Link) addrRouter { return failRouteReplace{&netlink.Handle{}} },
		"address delete": func(nic netlink.Link) addrRouter { return failAddrDel{&netlink.Handle{}, nic} },
	} {
		t.Run(name, func(t *testing.T) {
			_, nic, _ := newVM(t)
			br := enslave(t, nic, "br-test")

			require.Error(t, moveAddrs(nlh(nic), nic, br))
			requireMoved(t, br, nic)
		})
	}
}

func TestMakeNetFinishesAnEarlierMove(t *testing.T) {
	vmMAC, nic, _ := newVM(t)
	// An earlier container's failed move left the bridge holding the card, and the card its address.
	enslave(t, nic, bridgeNameFromMAC(vmMAC.String()))

	_, err := makeNet(nwcfg.Network{VmMAC: vmMAC.String(), MAC: "0a:00:00:00:00:03"})
	require.NoError(t, err)

	br, err := netlink.LinkByName(bridgeNameFromMAC(vmMAC.String()))
	require.NoError(t, err)
	requireMoved(t, nic, br)
}

func TestLinkByMACSkipsTheCardsBridge(t *testing.T) {
	origin := lockThread(t)
	require.NoError(t, netns.Set(newNetNS(t, origin)))

	mac, _ := net.ParseMAC("0a:00:00:00:00:02")
	require.NoError(t, netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-test", HardwareAddr: mac}}))
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "nic0", HardwareAddr: mac}, PeerName: "gw0"}))

	link, err := linkByMAC(nil, mac.String())
	require.NoError(t, err)
	assert.Equal(t, "nic0", link.Attrs().Name)
}

// failRouteReplace fails every route move, as a kernel refusal would.
type failRouteReplace struct{ *netlink.Handle }

func (failRouteReplace) RouteReplace(*netlink.Route) error { return unix.ENETUNREACH }

// failAddrDel fails deleting an address from link, after the routes moved.
type failAddrDel struct {
	*netlink.Handle
	link netlink.Link
}

func (f failAddrDel) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	if link.Attrs().Index == f.link.Attrs().Index {
		return unix.EBUSY
	}
	return f.Handle.AddrDel(link, addr)
}

// newVM leaves the test's thread in a new namespace holding the VM's card,
// nic0 at 172.17.0.2/29 with a default route through the gateway at
// 172.17.0.1, whose listening address it returns.
func newVM(t *testing.T) (net.HardwareAddr, netlink.Link, string) {
	t.Helper()

	origin := lockThread(t)
	gateway := newNetNS(t, origin)
	vm := newNetNS(t, origin)
	vmMAC, _ := net.ParseMAC("0a:00:00:00:00:02")

	require.NoError(t, netns.Set(vm))
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "nic0", HardwareAddr: vmMAC},
		PeerName:      "gw0",
		PeerNamespace: netlink.NsFd(gateway),
	}))
	nic, err := netlink.LinkByName("nic0")
	require.NoError(t, err)
	addAddr(t, nic, "172.17.0.2/29")
	require.NoError(t, netlink.LinkSetUp(nic))
	require.NoError(t, netlink.RouteAdd(&netlink.Route{Scope: unix.RT_SCOPE_UNIVERSE, Gw: net.ParseIP("172.17.0.1")}))

	require.NoError(t, netns.Set(gateway))
	gw, err := netlink.LinkByName("gw0")
	require.NoError(t, err)
	addAddr(t, gw, "172.17.0.1/29")
	require.NoError(t, netlink.LinkSetUp(gw))
	ln, err := net.Listen("tcp4", "172.17.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	require.NoError(t, netns.Set(vm))
	return vmMAC, nic, ln.Addr().String()
}

// enslave puts nic on a new bridge named name, with nic's MAC, as
// addBridgeNetwork does before it moves the addresses.
func enslave(t *testing.T, nic netlink.Link, name string) netlink.Link {
	t.Helper()

	require.NoError(t, netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name, HardwareAddr: nic.Attrs().HardwareAddr}}))
	br, err := netlink.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetMaster(nic, br))
	require.NoError(t, netlink.LinkSetUp(br))
	return br
}

// requireMoved checks that to holds the VM's address and default route, and
// from holds neither.
func requireMoved(t *testing.T, from, to netlink.Link) {
	t.Helper()

	toAddrs, err := netlink.AddrList(to, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.Len(t, toAddrs, 1)
	assert.Equal(t, "172.17.0.2/29", toAddrs[0].IPNet.String())

	fromAddrs, err := netlink.AddrList(from, netlink.FAMILY_V4)
	require.NoError(t, err)
	assert.Empty(t, fromAddrs)

	routes, err := netlink.RouteGet(net.ParseIP("192.0.2.1"))
	require.NoError(t, err)
	require.NotEmpty(t, routes)
	assert.Equal(t, to.Attrs().Index, routes[0].LinkIndex, "default route")
}

// lockThread locks the test to its thread and returns the thread's namespace,
// which the thread goes back to when the test ends.
func lockThread(t *testing.T) netns.NsHandle {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("creating network namespaces requires root")
	}

	runtime.LockOSThread()
	origin, err := netns.Get()
	require.NoError(t, err)
	t.Cleanup(func() {
		// A thread left in another namespace stays locked and exits with the test.
		if netns.Set(origin) == nil {
			runtime.UnlockOSThread()
		}
		_ = origin.Close()
	})
	return origin
}

// newNetNS creates a network namespace and returns the calling thread to origin.
func newNetNS(t *testing.T, origin netns.NsHandle) netns.NsHandle {
	t.Helper()

	ns, err := netns.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = ns.Close() })
	require.NoError(t, netns.Set(origin))
	return ns
}

func addAddr(t *testing.T, link netlink.Link, prefix string) {
	t.Helper()

	addr, err := netlink.ParseAddr(prefix)
	require.NoError(t, err)
	addr.Flags = unix.IFA_F_PERMANENT | unix.IFA_F_NODAD
	require.NoError(t, netlink.AddrAdd(link, addr))
}
