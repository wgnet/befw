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
	"bufio"
	"fmt"
	"github.com/wgnet/befw/logging"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var OverrideConfig = make(map[string]string)

type config struct {
	ConsulAddr     string
	ConsulDC       string
	NodeName       string
	NodeDC         string
	ConsulToken    string
	ServicesDir    string
	IPSetDir       string
	RulesPath      string
	WhitelistIPSet []string
	StaticSetList  []staticIPSetConf
	Timeout        befwConfigTimoutType
	NIDSEnable     bool
}

type befwServiceProto string
type portRange string
type RefreshMethod int8



type serviceClient struct {
	clientCIDR   *net.IPNet
	clientExpiry int64
}

type service struct {
	ServiceName     string           `json:"name"`
	ServiceMode     string           `json:"mode"`
	ServiceProtocol befwServiceProto `json:"protocol"`
	ServicePort     uint16           `json:"port"`
	ServicePorts    []befwPort           `json:"ports"`
	serviceClients  []serviceClient
}

type befwPort struct {
	Port	  portRange
	RawPort   json.RawMessage  `json:"port"`
	PortProto befwServiceProto `json:"protocol"`
}

type befwConfigTimoutType struct {
	Consul      time.Duration
	ConsulWatch time.Duration
}

func PortsAsStrings(ports []portRange) []string {
	buf := make([]string, len(ports))
	for i, _ := range ports {
		buf[i] = string(ports[i])
	}
	return buf
}

func (self *service) toString() string {
	s := new(strings.Builder)
	s.WriteString(fmt.Sprintf("Service '%s'. Ports: ", self.ServiceName))
	s.WriteString(fmt.Sprintf("%d/%s", self.ServicePort, self.ServiceProtocol))
	for _, p := range self.ServicePorts {
		s.WriteString(" ")
		s.WriteString(p.toString())
	}
	return s.String()
}

func (self *befwPort) toTag() string {
	return fmt.Sprintf("%s/%s", self.Port, self.PortProto)
}

func PortFromTag(tag string) (*befwPort, error)  {
	p := strings.Split(tag, "/")
	if len(p) != 2 {return nil, errors.New("Expected format: '<port>/<protocol>'.")}

	dport := portRange(p[0])
	proto := befwServiceProto(strings.ToLower(p[1]))

	if proto != ipprotoTcp && proto != ipprotoUdp {return nil, errors.New("Expected protocol: 'tcp' or 'udp' in '<port>/<protocol>'.")}
	p = strings.Split(string(dport), ":")
	if len(p) > 2 {return nil, errors.New("Expected port/s: '<num>' or '<num>:<num>' (num range is 0-65535) in  '<port>/<protocol>'")}
	for _, portNum := range p {
		num, err := strconv.Atoi(portNum); 
		if err != nil {return nil, errors.New("Port is not a number 0-65535")}
		if num <=0 || num > 65535 {return nil, errors.New("Expected port/s: '<num>' or '<num>:<num>' (num range is 0-65535) in  '<port>/<protocol>'")}
	}
	return &befwPort {
		Port:		dport,
		RawPort:	nil,
		PortProto:	proto,
	}, nil
}

func (self *befwPort) toString() string {
	return self.toTag()
}

func (self *befwPort) Prepare() {
	raw := string(self.RawPort)
	raw = strings.Trim(raw, "\"")
	self.Port = portRange(raw)
}

func  ServiceFromJson(data []byte) (*service, error) {
	var v service
	e := json.Unmarshal(data, &v); 
	if e != nil { return nil, errors.New("Bad JSON with service.") } 

	var first *befwPort
	if v.ServicePorts != nil {
		for i := range v.ServicePorts {
			v.ServicePorts[i].Prepare()
			if first == nil { first = &v.ServicePorts[i] }
			if v.ServicePorts[i].PortProto == "" {
				v.ServicePorts[i].PortProto = ipprotoTcp
			}
		}
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
		if first == nil { return nil, errors.New("Expected not empty 'port' or 'ports' fields.") }
		port := strings.Split(string(first.Port), ":")
		value, err := strconv.Atoi(port[0])
		if err != nil { return nil, errors.New("Bad port in ports.") }
		v.ServicePort = uint16(value)
	}
	return &v, nil

}


func createConfig(configFile string) *config {
	ret := &config{
		ConsulAddr:     consulAddress,
		ConsulDC:       aclDatacenter,
		ConsulToken:    "",
		IPSetDir:       staticIpsetPath,
		ServicesDir:    staticServicesPath,
		RulesPath:      staticRulesPath,
		WhitelistIPSet: make([]string, 0),
		StaticSetList:  staticIPSetList, // default, TODO: make a Config
		Timeout: befwConfigTimoutType{
			Consul:      5 * 60 * time.Second,
			ConsulWatch: 10 * 60 * time.Second,
		},
	}
	kv := make(map[string]string)
	if configFile == "" {
		return ret
	}
	if f, e := os.Open(configFile); e != nil {
		logging.LogWarning("[Config] can't open", configFile, ":", e.Error())
		return ret
	} else {
		defer f.Close()
		r := bufio.NewScanner(f)
		for r.Scan() {
			l := r.Text()
			if !strings.HasPrefix(l, "#") {
				if strings.IndexByte(l, '=') > 0 {
					v2 := strings.Split(l, "=")
					kv[strings.Trim(v2[0], "\r\n\t ")] = strings.Trim(strings.Join(v2[1:], "="), "\r\n\t ")
				}
			}
		}
		setConfigKV(&ret.ConsulAddr, "address", OverrideConfig, kv)
		setConfigKV(&ret.ConsulDC, "dc", OverrideConfig, kv)
		setConfigKV(&ret.ConsulToken, "token", OverrideConfig, kv)
		setConfigKV(&ret.IPSetDir, "ipsets", OverrideConfig, kv)
		setConfigKV(&ret.ServicesDir, "services", OverrideConfig, kv)
		setConfigKV(&ret.RulesPath, "rules", OverrideConfig, kv)
		setConfigKV(&ret.NodeName, "nodename", OverrideConfig, kv)
		setConfigKV(&ret.NodeDC, "nodedc", OverrideConfig, kv)
		setConfigKVSeconds(&ret.Timeout.Consul, "consul_timeout_sec", OverrideConfig, kv)
		setConfigKVSeconds(&ret.Timeout.ConsulWatch, "consulwatch_timeout_sec", OverrideConfig, kv)
		setConfigKVBool(&ret.NIDSEnable, "nids", OverrideConfig, kv)

		if _, ok := kv["fail"]; ok {
			logging.LogError("[Config] you must edit your Config file before proceed")
		}
		n := 3
		for k, v := range kv {
			if confSetPrefix+allowIPSetName == k {
				v0 := strings.Split(v, ";")
				ret.WhitelistIPSet = v0
				continue
			}
			if strings.HasPrefix(k, confSetPrefix) {
				set := staticIPSetConf{Name: strings.TrimPrefix(k, confSetPrefix)}
				v0 := strings.Split(v, ";")
				if len(v0) == 1 {
					set.Priority = n
					set.Target = v0[0]
				} else {
					if n, e := strconv.Atoi(v0[0]); e == nil {
						set.Priority = n
						set.Target = v0[1]
					} else {
						continue
					}
				}
				logging.LogDebug("New local set: ", set.Name)
				ret.StaticSetList = append(ret.StaticSetList, set)
				n += 1
			}
		}
	}
	return ret
}

func setConfigKV(dest *string, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			*dest = value
			return
		}
	}
}
func setConfigKVBool(dest *bool, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			if b, e := strconv.ParseBool(value); e == nil {
				*dest = b
			}
			return
		}
	}
}

func setConfigKVSeconds(dest *time.Duration, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			if i, err := strconv.Atoi(value); err == nil {
				*dest = time.Duration(i) * time.Second
				return
			}
		}
	}
}
