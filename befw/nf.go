/**
 * Copyright 2018-2019 Wargaming Group Limited
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
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type serviceUnknownClient struct {
	service *service
	clients map[string]int
}

var serviceClients = make(map[string]*serviceUnknownClient)
var tcpServiceLinks = make(map[uint16]*serviceUnknownClient)
var udpServiceLinks = make(map[uint16]*serviceUnknownClient)
var serviceClientsLock = new(sync.RWMutex)

var serviceNil = &serviceUnknownClient{
	service: nil,
	clients: make(map[string]int),
}

func (this *service) registerNflog() {
	serviceClientsLock.Lock()
	defer serviceClientsLock.Unlock()
	logging.LogDebug(fmt.Sprintf("[NF] Registering service %s @ %d/%s", this.ServiceName, this.ServicePort, this.ServiceProtocol))
	if _, ok := serviceClients[this.ServiceName]; ok {
		return
	}
	serviceClients[this.ServiceName] = &serviceUnknownClient{
		service: this,
		clients: make(map[string]int),
	}
	if this.ServiceProtocol == ipprotoTcp {
		tcpServiceLinks[this.ServicePort] = serviceClients[this.ServiceName]
	} else {
		udpServiceLinks[this.ServicePort] = serviceClients[this.ServiceName]
	}
	for _, k := range this.ServicePorts {
		if k.PortProto == ipprotoTcp {
			tcpServiceLinks[k.Port] = serviceClients[this.ServiceName]
		} else {
			udpServiceLinks[k.Port] = serviceClients[this.ServiceName]
		}
	}
}

func findServiceByPort(port uint16, protocol befwServiceProto) *serviceUnknownClient {
	serviceClientsLock.RLock()
	defer serviceClientsLock.RUnlock()
	if protocol == ipprotoTcp {
		if _, ok := tcpServiceLinks[port]; ok {
			return tcpServiceLinks[port]
		}
	} else {
		if _, ok := udpServiceLinks[port]; ok {
			return udpServiceLinks[port]
		}
	}
	return serviceNil
}

func nflogCallback(payload *nflog.Payload) int {
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	var protocol befwServiceProto
	var port uint16 = 0
	var src string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src = ip.SrcIP.String()
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = ipprotoTcp
		tcp, _ := tcpLayer.(*layers.TCP)
		port = uint16(tcp.DstPort)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		protocol = ipprotoUdp
		udp, _ := udpLayer.(*layers.UDP)
		port = uint16(udp.DstPort)
	}
	if port > 0 {
		srv := findServiceByPort(port, protocol)
		if srv != nil {
			if _, ok := srv.clients[src]; !ok {
				srv.clients[src] = 0
			}
			srv.clients[src]++
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

func serviceHeader(svc *service) string {
	sb := strings.Builder{}
	sb.WriteString("Service: ")
	sb.WriteString(svc.ServiceName)
	sb.WriteString("\nPorts: ")
	sb.WriteString(strconv.Itoa(int(svc.ServicePort)))
	sb.WriteByte('/')
	sb.WriteString(string(svc.ServiceProtocol))
	for _, k := range svc.ServicePorts {
		sb.WriteString(", ")
		sb.WriteString(strconv.Itoa(int(k.Port)))
		sb.WriteByte('/')
		sb.WriteString(string(k.PortProto))
	}
	return sb.String()
}
func syncData() { // client function
	serviceClientsLock.RLock()
	defer serviceClientsLock.RUnlock()
	os.MkdirAll(befwState, 0755)
	for name, svc := range serviceClients {
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
	serviceClientsLock.Lock()
	defer serviceClientsLock.Unlock()
	for _, v := range serviceClients {
		for i := range v.clients {
			delete(v.clients, i)
		}
	}
	for i := range serviceNil.clients {
		delete(serviceNil.clients, i)
	}
	logging.LogInfo("[NF] Services stats have been wiped")
}
