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
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type config struct {
	ConsulAddr    string
	ConsulDC      string
	ConsulToken   string
	ServicesDir   string
	IPSetDir      string
	RulesPath     string
	StaticSetList []staticIPSetConf
}

type befwServiceProto string

type RefreshMethod int8

type serviceClient struct {
	clientCIDR   *net.IPNet
	clientExpiry int64
}

type service struct {
	ServiceName     string           `json:"Name"`
	ServiceProtocol befwServiceProto `json:"protocol"`
	ServicePort     uint16           `json:"port"`
	ServicePorts    []port           `json:"ports"`
	serviceClients  []serviceClient
}

type port struct {
	Port      int              `json:"port"`
	PortProto befwServiceProto `json:"protocol"`
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

func createConfig(configFile string) *config {
	ret := &config{
		ConsulAddr:    consulAddress,
		ConsulDC:      aclDatacenter,
		ConsulToken:   "",
		IPSetDir:      staticIpsetPath,
		ServicesDir:   staticServicesPath,
		RulesPath:     staticRulesPath,
		StaticSetList: staticIPSetList, // default, TODO: make a Config
	}
	kv := make(map[string]string)
	if configFile == "" {
		return ret
	}
	if f, e := os.Open(configFile); e != nil {
		LogWarning("[Config] can't open", configFile, ":", e.Error())
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
		if v, ok := kv["address"]; ok {
			ret.ConsulAddr = v
		}
		if v, ok := kv["dc"]; ok {
			ret.ConsulDC = v
		}
		if v, ok := kv["token"]; ok {
			ret.ConsulToken = v
		}
		if v, ok := kv["IPSets"]; ok {
			ret.IPSetDir = v
		}
		if v, ok := kv["services"]; ok {
			ret.ServicesDir = v
		}
		if v, ok := kv["rules"]; ok {
			ret.RulesPath = v
		}
		if _, ok := kv["fail"]; ok {
			LogError("[Config] you must edit your Config file before proceed")
		}
		n := 3
		for k, v := range kv {
			if strings.HasPrefix(k, "set.") {
				set := staticIPSetConf{Name: strings.TrimPrefix(k, "set.")}
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
				LogDebug("New local set: ", set.Name)
				ret.StaticSetList = append(ret.StaticSetList, set)
				n += 1
			}
		}
	}
	return ret
}
