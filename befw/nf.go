/**
 * Copyright 2018-2021 Wargaming Group Limited
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
	"fmt"
	"github.com/chifflier/nflog-go/nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/wgnet/befw/logging"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
)

type serviceUnknownClient struct {
	service *bService
	clients map[string]int
}

var allServiceClients = make(map[string]*serviceUnknownClient)
var serviceByTCP = make(map[netPort]*serviceUnknownClient)
var serviceByUDP = make(map[netPort]*serviceUnknownClient)

var lockServiceClients = new(sync.RWMutex)

var serviceNil = &serviceUnknownClient{
	service: nil,
	clients: make(map[string]int),
}

func (this *bService) nflogRegister() {
	lockServiceClients.Lock()
	defer lockServiceClients.Unlock()
	logging.LogDebug(fmt.Sprintf("[NF] Registering service %s (%s)", this.Name,
		toTags(this.Ports)))
	if _, ok := allServiceClients[this.Name]; ok {
		return
	}
	allServiceClients[this.Name] = &serviceUnknownClient{
		service: this,
		clients: make(map[string]int),
	}
}

func findServiceByPort(port netPort, protocol netProtocol) *serviceUnknownClient {
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

func nflogCallback(payload *nflog.Payload) int {
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	var protocol netProtocol
	var port netPort = 0
	var src net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src = ip.SrcIP
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = PROTOCOL_TCP
		tcp, _ := tcpLayer.(*layers.TCP)
		port = netPort(tcp.DstPort)
		if tcp.SYN && !tcp.ACK { // synscan only
			nidsNFCallback(int(port), src)
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		protocol = PROTOCOL_UDP
		udp, _ := udpLayer.(*layers.UDP)
		port = netPort(udp.DstPort)
	}
	if port > 0 {
		srv := findServiceByPort(port, protocol)
		if srv != nil {
			if _, ok := srv.clients[src.String()]; !ok {
				srv.clients[src.String()] = 0
			}
			srv.clients[src.String()]++
		}
	}

	return 0
}

func StartNFLogger() {
	q := new(nflog.Queue)
	q.SetCallback(nflogCallback)
	q.Init()
	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)
	q.CreateQueue(befwNFQueue)
	q.SetMode(nflog.NFULNL_COPY_PACKET)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.Close()
			os.Exit(0)
			// XXX we should break gracefully from loop
		}
	}()
	go q.TryRun()
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			syncData()
		}
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

func syncData() { // client function
	lockServiceClients.RLock()
	defer lockServiceClients.RUnlock()
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
	lockServiceClients.Lock()
	defer lockServiceClients.Unlock()
	for _, v := range allServiceClients {
		for i := range v.clients {
			delete(v.clients, i)
		}
	}
	for i := range serviceNil.clients {
		delete(serviceNil.clients, i)
	}
	logging.LogInfo("[NF] Services stats have been wiped")
}
