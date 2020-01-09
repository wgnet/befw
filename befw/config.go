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
	"time"
)

var OverrideConfig = make(map[string]string)

type config struct {
	ConsulAddr    string
	ConsulDC      string
	NodeName      string
	NodeDC        string
	ConsulToken   string
	ServicesDir   string
	IPSetDir      string
	RulesPath     string
	StaticSetList []staticIPSetConf
	Timeout       befwConfigTimoutType
}

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

type befwConfigTimoutType struct {
	Consul      time.Duration
	ConsulWatch time.Duration
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
		setConfigKV(&ret.ConsulAddr,  "address", OverrideConfig, kv)
		setConfigKV(&ret.ConsulDC,  "dc", OverrideConfig, kv)
		setConfigKV(&ret.ConsulToken,  "token", OverrideConfig, kv)
		setConfigKV(&ret.IPSetDir,  "ipsets", OverrideConfig, kv)
		setConfigKV(&ret.ServicesDir,  "services", OverrideConfig, kv)
		setConfigKV(&ret.RulesPath,  "rules", OverrideConfig, kv)
		setConfigKV(&ret.NodeName,  "nodename", OverrideConfig, kv)
		setConfigKV(&ret.NodeDC,  "nodedc", OverrideConfig, kv)
		setConfigKVSeconds(&ret.Timeout.Consul,  "consul_timeout_sec", OverrideConfig, kv)
		setConfigKVSeconds(&ret.Timeout.ConsulWatch,  "consulwatch_timeout_sec", OverrideConfig, kv)

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

func setConfigKV(dest *string, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			*dest = value
			return
		}
	}
}

func setConfigKVSeconds(dest *time.Duration, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			if i, err := strconv.Atoi(value); err == nil {
				*dest = time.Duration( i ) * time.Second
				return
			}
		}
	}
}