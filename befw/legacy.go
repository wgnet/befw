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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type befwServiceProto string // DEPRECATED
type portRange string        // DEPRECATED

// DEPRECATED. Use bService instead.
type legacyService struct {
	ServiceName     string           `json:"name"`
	ServiceMode     string           `json:"mode"`
	ServiceProtocol befwServiceProto `json:"protocol"` // DEPRECATED
	ServicePort     uint16           `json:"port"`     // DEPRECATED
	ServicePorts    []legacyBefwPort
	RawServicePorts []interface{} `json:"ports"`
	serviceClients  []bClient
}

// DEPRECATED: Use bPort instead
type legacyBefwPort struct {
	Port      portRange
	RawPort   json.RawMessage  `json:"port"`
	PortProto befwServiceProto `json:"protocol"`
}

// DEPRECATED
func PortsAsStrings(ports []portRange) []string {
	buf := make([]string, len(ports))
	for i, _ := range ports {
		buf[i] = string(ports[i])
	}
	return buf
}

// DEPRECATED
func PortFromTag(tag string) (*legacyBefwPort, error) {
	p := strings.Split(tag, "/")
	if len(p) != 2 {
		return nil, fmt.Errorf("Expected format: '<port>/<protocol>'.")
	}

	dport := portRange(p[0])
	proto := befwServiceProto(strings.ToLower(p[1]))

	if proto != ipprotoTcp && proto != ipprotoUdp {
		return nil, fmt.Errorf("Expected protocol: 'tcp' or 'udp' in '<port>/<protocol>'.")
	}
	p = strings.Split(string(dport), ":")
	if len(p) > 2 {
		return nil, fmt.Errorf("Expected port/s: '<num>' or '<num>:<num>' (num range is 0-65535) in  '<port>/<protocol>'")
	}
	for _, portNum := range p {
		num, err := strconv.Atoi(portNum)
		if err != nil {
			return nil, fmt.Errorf("Port is not a number 0-65535")
		}
		if num <= 0 || num > 65535 {
			return nil, fmt.Errorf("Expected port/s: '<num>' or '<num>:<num>' (num range is 0-65535) in  '<port>/<protocol>'")
		}
	}
	return &legacyBefwPort{
		Port:      dport,
		RawPort:   nil,
		PortProto: proto,
	}, nil
}

// Generate bService from JSON
func ServiceFromJson(data []byte) (*bService, error) {
	srv, err := LegacyServiceFromJson(data)
	if err != nil {
		return nil, err
	}
	return srv.toBService()
}

// Convert legacyService to bService
func (s legacyService) toBService() (*bService, error) {
	var ports []bPort
	// Defaul port (JSON: `{... port: 123, protocol: "tcp" ...}`)
	defaultPort, err := NewBPort(fmt.Sprintf("%d/%s", s.ServicePort, s.ServiceProtocol))
	if err != nil {
		return nil, err
	}
	ports = append(ports, *defaultPort)
	// Multiports (JSON: `{... ports: ["123:456/udp", {port: 1, protocol: "tcp"}] ...}`)
	for _, port := range s.ServicePorts {
		bp, err := NewBPort(port.toTag())
		if err != nil {
			return nil, err
		}
		ports = append(ports, *bp)
	}

	result := &bService{
		Name:  s.ServiceName,
		Ports: ports,
		Mode:  getModeFromTags([]string{s.ServiceMode}),
	}
	return result, nil
}

// DEPRECATED
func LegacyServiceFromJson(data []byte) (*legacyService, error) {
	var v legacyService
	e := json.Unmarshal(data, &v)
	if e != nil {
		return nil, fmt.Errorf("Bad JSON with service.")
	}

	var first *legacyBefwPort
	if v.RawServicePorts != nil {
		for _, rawPort := range v.RawServicePorts {
			var bp *legacyBefwPort
			switch rawPort.(type) {
			case string:
				bpp, err := NewBPort(rawPort.(string))
				if err != nil {
					return nil, err
				}
				bp = &legacyBefwPort{
					Port:      portRange(bpp.Range()),
					RawPort:   nil,
					PortProto: befwServiceProto(bpp.Protocol),
				}
			case map[string]interface{}:
				mapPort := rawPort.(map[string]interface{})
				var port, prot string
				prot = "tcp"
				if n, ok := mapPort["port"]; ok {
					switch n.(type) {
					case float64:
						port = fmt.Sprintf("%d", uint16(n.(float64)))
					case string:
						port = n.(string)
					}
				}
				if v, ok := mapPort["protocol"]; ok {
					prot = v.(string)
				}
				var err error
				bp, err = PortFromTag(fmt.Sprintf("%s/%s", port, prot))
				if err != nil {
					return nil, err
				}
			}
			if bp != nil {
				v.ServicePorts = append(v.ServicePorts, *bp)
			}
		}
	}
	if len(v.ServicePorts) > 0 && first == nil {
		first = &v.ServicePorts[0]
	}

	if v.ServiceMode == "" {
		v.ServiceMode = "default"
	}
	if v.ServiceProtocol == "" {
		if first == nil {
			v.ServiceProtocol = ipprotoTcp
		} else {
			v.ServiceProtocol = first.PortProto
		}
	}
	if v.ServicePort == 0 {
		if first == nil {
			return nil, fmt.Errorf("Expected not empty 'port' or 'ports' fields.")
		}
		port := strings.Split(string(first.Port), ":")
		value, err := strconv.Atoi(port[0])
		if err != nil {
			return nil, fmt.Errorf("Bad port in ports.")
		}
		v.ServicePort = uint16(value)
	}
	return &v, nil
}

func (self *legacyBefwPort) toString() string {
	return self.toTag()
}

func (self *legacyBefwPort) Prepare() {
	raw := string(self.RawPort)
	raw = strings.Trim(raw, "\"")
	self.Port = portRange(raw)
}

func (self *legacyService) toString() string {
	s := new(strings.Builder)
	s.WriteString(fmt.Sprintf("Service '%s'. Ports: ", self.ServiceName))
	s.WriteString(fmt.Sprintf("%d/%s", self.ServicePort, self.ServiceProtocol))
	for _, p := range self.ServicePorts {
		s.WriteString(" ")
		s.WriteString(p.toString())
	}
	return s.String()
}

func (self *legacyBefwPort) toTag() string {
	return fmt.Sprintf("%s/%s", self.Port, self.PortProto)
}
