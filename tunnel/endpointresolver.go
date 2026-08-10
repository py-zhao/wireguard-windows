/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"
	"net/netip"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type endpointDNSMonitorEntry struct {
	peerIndex  int
	hostname   string
	resolvedIP string
}

type endpointDNSMonitor struct {
	entries []endpointDNSMonitorEntry
}

func newEndpointDNSMonitor(config *conf.Config) *endpointDNSMonitor {
	monitor := &endpointDNSMonitor{}
	for peerIndex := range config.Peers {
		host := config.Peers[peerIndex].Endpoint.Host
		if host == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		monitor.entries = append(monitor.entries, endpointDNSMonitorEntry{
			peerIndex: peerIndex,
			hostname:  host,
		})
	}
	return monitor
}

func (monitor *endpointDNSMonitor) initialize(config *conf.Config) {
	for i := range monitor.entries {
		monitor.entries[i].resolvedIP = config.Peers[monitor.entries[i].peerIndex].Endpoint.Host
	}
}

func endpointUpdateConfiguration(peer *conf.Peer, addr netip.Addr) (*driver.Interface, uint32) {
	var endpoint winipcfg.RawSockaddrInet
	endpoint.SetAddrPort(netip.AddrPortFrom(addr, peer.Endpoint.Port))

	var builder driver.ConfigBuilder
	builder.AppendInterface(&driver.Interface{PeerCount: 1})
	builder.AppendPeer(&driver.Peer{
		Flags:     driver.PeerHasPublicKey | driver.PeerHasEndpoint | driver.PeerUpdateOnly,
		PublicKey: peer.PublicKey,
		Endpoint:  endpoint,
	})
	return builder.Interface()
}

func (monitor *endpointDNSMonitor) refresh(adapter *driver.Adapter, config *conf.Config, watcher *interfaceWatcher) {
	for i := range monitor.entries {
		entry := &monitor.entries[i]
		resolvedIP, err := conf.ResolveEndpointHostname(entry.hostname)
		if err != nil {
			log.Printf("Unable to refresh endpoint hostname %s: %v", entry.hostname, err)
			continue
		}
		if resolvedIP == entry.resolvedIP {
			continue
		}

		addr, err := netip.ParseAddr(resolvedIP)
		if err != nil {
			log.Printf("Unable to use refreshed endpoint hostname %s: %v", entry.hostname, err)
			continue
		}

		watcher.setupMutex.Lock()
		peer := &config.Peers[entry.peerIndex]
		err = adapter.SetConfiguration(endpointUpdateConfiguration(peer, addr))
		if err == nil {
			oldIP := entry.resolvedIP
			entry.resolvedIP = resolvedIP
			peer.Endpoint.Host = resolvedIP
			log.Printf("Endpoint hostname %s changed from %s to %s; endpoint updated", entry.hostname, oldIP, resolvedIP)
		}
		watcher.setupMutex.Unlock()

		if err != nil {
			log.Printf("Unable to update endpoint hostname %s to %s: %v", entry.hostname, resolvedIP, err)
		}
	}
}
