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
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"
)

type serviceUnknownClient struct {
	service *service
	clients map[string]int
}

var serviceClients = make(map[string]*serviceUnknownClient)
var serviceClientsLock = new(sync.RWMutex)

func (this *service) registerNflog() {
	serviceClientsLock.Lock()
	defer serviceClientsLock.Unlock()
	LogInfo(fmt.Sprintf("[NF] Registering service %s @ %d/%s", this.ServiceName, this.ServicePort, this.ServiceProtocol))
	if _, ok := serviceClients[this.ServiceName]; ok {
		return
	}
	serviceClients[this.ServiceName] = &serviceUnknownClient{
		service: this,
		clients: make(map[string]int),
	}

}

func findServiceByPort(port uint16, protocol befwServiceProto) *serviceUnknownClient {
	serviceClientsLock.RLock()
	defer serviceClientsLock.RUnlock()
	for _, v := range serviceClients {
		if v.service.ServiceProtocol == protocol {
			if v.service.ServicePort == port {
				return v
			}
		}
	}
	return nil
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

func syncData() { // client function
	serviceClientsLock.RLock()
	defer serviceClientsLock.RUnlock()
	os.MkdirAll(befwState, 0755)
	for name, svc := range serviceClients {
		filename := path.Join(befwState, name)
		os.Remove(filename)
		if fd, e := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644); e == nil {
			fmt.Fprintf(fd, "Service: %s\nProtocol: %s\nPort: %d\nTotal missing: %d\n\n",
				svc.service.ServiceName,
				svc.service.ServiceProtocol, svc.service.ServicePort,
				len(svc.clients))
			for ip, num := range svc.clients {
				fmt.Fprintf(fd, " * %s - %d packets\n", ip, num)
			}
			fd.Close()
		} else {
			LogWarning("[NF] Can't write data to", filename, ":", e.Error())
			break // skip
		}
	}
	LogInfo("[NF] Services stats have been written")

}

func cleanupMissing() {
	serviceClientsLock.Lock()
	defer serviceClientsLock.Unlock()
	for _, v := range serviceClients {
		for i, _ := range v.clients {
			delete(v.clients, i)
		}
	}
	LogInfo("[NF] Services stats have been wiped")
}
