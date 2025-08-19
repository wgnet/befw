/**
 * Copyright 2018-2023 Wargaming Group Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/
package befw

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"github.com/wgnet/befw/logging"
)

var pktCh chan pktEvent
var regCh = make(chan *bService, MAX_PORT)
var wipeCh = make(chan struct{}, 1)

type pktEvent struct {
	port  netPort
	proto netProtocol
	srcIP string
}

type serviceUnknownClient struct {
	service *bService
	clients map[string]int
}

func (svc *bService) nflogRegister() {
	// copy bService to use it safely inside packetProcessor gorutine
	immutableSvc := svc.DeepCopy()
	regCh <- immutableSvc
}

func (svc *bService) DeepCopy() *bService {
	if svc == nil {
		return nil
	}
	portsCopy := make([]bPort, len(svc.Ports))
	copy(portsCopy, svc.Ports)

	clientsCopy := make([]bClient, len(svc.Clients))
	for i, client := range svc.Clients {
		var cidrCopy *net.IPNet
		if client.CIDR != nil {
			ipCopy := make(net.IP, len(client.CIDR.IP))
			copy(ipCopy, client.CIDR.IP)

			maskCopy := make(net.IPMask, len(client.CIDR.Mask))
			copy(maskCopy, client.CIDR.Mask)

			cidrCopy = &net.IPNet{
				IP:   ipCopy,
				Mask: maskCopy,
			}
		}

		clientsCopy[i] = bClient{
			CIDR:   cidrCopy,
			Expiry: client.Expiry,
		}
	}
	return &bService{
		Name:    svc.Name,
		Ports:   portsCopy,
		Clients: clientsCopy,
		Mode:    svc.Mode,
	}
}

func findServiceByPort(port netPort, protocol netProtocol,
	serviceByTCP map[netPort]*serviceUnknownClient,
	serviceByUDP map[netPort]*serviceUnknownClient,
	allServiceClients map[string]*serviceUnknownClient,
	serviceNil *serviceUnknownClient) *serviceUnknownClient {
	var lookup map[netPort]*serviceUnknownClient
	if protocol == PROTOCOL_TCP {
		lookup = serviceByTCP
	} else if protocol == PROTOCOL_UDP {
		lookup = serviceByUDP
	} else {
		return serviceNil
	}
	if _, ok := lookup[port]; ok {
		return lookup[port]
	}

	var result *serviceUnknownClient = serviceNil
	lookupPort, err := NewBPort(fmt.Sprintf("%d/%s", port, protocol))
	if err != nil { /* Unexpected */
		return result
	}
FindPortLoop:
	for _, srv := range allServiceClients {
		for _, srvPort := range srv.service.Ports {
			if srvPort.IsIntersect(lookupPort) {
				result = srv
				break FindPortLoop
			}
		}
	}
	lookup[port] = result
	return result
}

func nflogCallback(attrs nflog.Attribute) int {
	var protocol netProtocol
	var port netPort = 0
	var src net.IP

	p := gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// logging.LogWarning("[NF] Non-IPv4 packet, skipping")
		return 0
	}
	ip, _ := ipLayer.(*layers.IPv4)
	src = ip.SrcIP
	if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = PROTOCOL_TCP
		tcp, _ := tcpLayer.(*layers.TCP)
		port = netPort(tcp.DstPort)
		if tcp.SYN && !tcp.ACK { // synscan only
			nidsNFCallback(int(port), src)
		}
	}
	if udpLayer := p.Layer(layers.LayerTypeUDP); udpLayer != nil {
		protocol = PROTOCOL_UDP
		udp, _ := udpLayer.(*layers.UDP)
		port = netPort(udp.DstPort)
	}
	if port > 0 {
		evt := pktEvent{port: port, proto: protocol, srcIP: src.String()}
		select {
		case pktCh <- evt:
		default:
			logging.LogWarning("[NF] Packet channel is full, dropping packets")
		}
	}
	return 0
}

func packetProcessor() {
	allServiceClients := make(map[string]*serviceUnknownClient)
	serviceByTCP := make(map[netPort]*serviceUnknownClient)
	serviceByUDP := make(map[netPort]*serviceUnknownClient)
	serviceNil := &serviceUnknownClient{service: nil, clients: make(map[string]int)}

	syncDataTk := time.NewTicker(1 * time.Minute)
	defer syncDataTk.Stop()
	for {
		select {
		case ev := <-pktCh:
			srv := findServiceByPort(ev.port, ev.proto,
				serviceByTCP, serviceByUDP,
				allServiceClients, serviceNil)
			srv.clients[ev.srcIP]++
		case svc := <-regCh:
			removeNilIntersections(PROTOCOL_TCP, serviceByTCP, svc)
			removeNilIntersections(PROTOCOL_UDP, serviceByUDP, svc)
			if _, ok := allServiceClients[svc.Name]; !ok {
				allServiceClients[svc.Name] =
					&serviceUnknownClient{service: svc, clients: make(map[string]int)}
			}
		case <-wipeCh:
			for _, v := range allServiceClients {
				v.clients = make(map[string]int)
			}
			serviceNil.clients = make(map[string]int)
			logging.LogInfo("[NF] Services stats have been wiped")
		case <-syncDataTk.C:
			syncData(allServiceClients, serviceNil)
		}
	}
}

// removeNilIntersections removes entries in serviceByTCP/serviceByUDP where the
// service is nil and the port intersects with the registered service.
// This handles race conditions where NFLOG sees packets before the service is registered.
func removeNilIntersections(protocol netProtocol,
	serviceMap map[netPort]*serviceUnknownClient,
	svc *bService) {
	for port, entry := range serviceMap {
		if entry.service != nil {
			continue
		}
		lookupPort, err := NewBPort(fmt.Sprintf("%d/%s", port, protocol))
		if err != nil {
			continue
		}
		for _, newPort := range svc.Ports {
			if newPort.IsIntersect(lookupPort) {
				logging.LogInfo(fmt.Sprintf(
					"[NF] Removing nil-service entry for port %d/%s (intersects with %s)",
					port, protocol, svc.Name))
				delete(serviceMap, port)
				break
			}
		}
	}
}

func StartNFLogger(nfEvenBuffer int) {
	go func() {
		config := nflog.Config{
			Group:    befwNFQueue,
			Copymode: nflog.CopyPacket,
		}

		nf, err := nflog.Open(&config)
		if err != nil {
			logging.LogError("[NF] Could not open nflog socket: ", err)
			return
		}
		// StartNFLogger is called once per befw run
		// on restart/stop kernel close netlink socket
		// so no need to close it as we are blocking until befw exit
		// defer nf.Close()

		// Avoid receiving ENOBUFS errors.
		if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
			logging.LogError(fmt.Sprintf("[NF] Failed to set netlink option %v: %v", netlink.NoENOBUFS, err))
			nf.Close()
			return
		}
		pktCh = make(chan pktEvent, nfEvenBuffer)

		hook := func(attrs nflog.Attribute) int {
			nflogCallback(attrs)
			return 0
		}
		errFunc := func(e error) int {
			logging.LogError("[NF] Received error on nflog hook: ", e)
			return 0
		}
		err = nf.RegisterWithErrorFunc(context.Background(), hook, errFunc)
		if err != nil {
			logging.LogError("[NF] Failed to register nflog hook function: ", err)
			nf.Close()
			return
		}
		go packetProcessor()
		// block until befw exit
		select {}
	}()
}

func serviceHeader(srv *bService) string {
	sb := strings.Builder{}
	sb.WriteString("Service: ")
	sb.WriteString(srv.Name)
	sb.WriteString("\nPorts: ")
	for i, port := range srv.Ports {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(port.toTag())
	}
	return sb.String()
}

func syncData(allServiceClients map[string]*serviceUnknownClient, serviceNil *serviceUnknownClient) { // client function
	os.MkdirAll(befwState, 0755)
	for name, svc := range allServiceClients {
		filename := path.Join(befwState, name)
		os.Remove(filename)
		if fd, e := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644); e == nil {
			fmt.Fprintf(fd, "%s\nTotal missing: %d\n\n",
				serviceHeader(svc.service),
				len(svc.clients))
			for ip, num := range svc.clients {
				fmt.Fprintf(fd, " * %s - %d packets\n", ip, num)
			}
			fd.Close()
		} else {
			logging.LogWarning("[NF] Can't write data to", filename, ":", e.Error())
			break // skip
		}
	}
	if len(serviceNil.clients) > 0 {
		filename := path.Join(befwState, befwNillService)
		os.Remove(filename)
		if fd, e := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644); e == nil {
			fmt.Fprintf(fd, "Service: NILL\nProtocol: ANY\nPort: ANY\nTotal missing: %d\n\n",
				len(serviceNil.clients))
			for ip, num := range serviceNil.clients {
				fmt.Fprintf(fd, " * %s - %d packets\n", ip, num)
			}
			fd.Close()
		} else {
			logging.LogWarning("[NF] Can't write data to", filename, ":", e.Error())
		}

	}
	//LogDebug("[NF] Services stats have been written")

}

func cleanupMissing() {
	select {
	case wipeCh <- struct{}{}:
	default:
	}
}
