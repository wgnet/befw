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
	"github.com/hashicorp/consul/api"
	"net"
	"strings"
	"time"
)

type befwServiceProto string

type RefreshMethod int8

type serviceClient struct {
	clientCIDR   *net.IPNet
	clientExpiry int64
}

type service struct {
	ServiceName     string           `json:"name"`
	ServiceProtocol befwServiceProto `json:"protocol"`
	ServicePort     uint16           `json:"port"`
	ServicePorts    []port           `json:"ports"`
	serviceClients  []serviceClient
}

type port struct {
	Port      int              `json:"port"`
	PortProto befwServiceProto `json:"protocol"`
}

type state struct {
	consulClient *api.Client
	nodeName     string
	nodeDC       string
	nodeServices []service
	ipsets       map[string][]string
	lastUpdated  time.Time
	config       *config
}

type config struct {
	consulAddr  string
	consulDC    string
	consulToken string
	servicesDir string
	ipsetDir    string
	rulesPath   string
}

type ipset struct {
	name   string
	ipList []*net.IPNet
}

func (self *service) toString() string {
	s := new(strings.Builder)
	s.WriteString(fmt.Sprintf("Service %s, port %d/%s", self.ServiceName, self.ServicePort, self.ServiceProtocol))
	for _, p := range self.ServicePorts {
		s.WriteString(p.toString())
	}
	return s.String()
}

func (self *port) toString() string {
	return fmt.Sprintf("%d/%s", self.Port, self.PortProto)
}
