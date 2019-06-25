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
	"errors"
	"fmt"
	"github.com/hashicorp/consul/api"
	"net"
	"strconv"
	"strings"
	"time"
)

type state struct {
	consulClient *api.Client
	nodeName     string
	nodeDC       string
	nodeServices []service
	ipsets       map[string][]string
	lastUpdated  time.Time
	config       *config
}

type ipset struct {
	name   string
	ipList []*net.IPNet
}

type staticIPSetConf struct {
	name     string
	priority int
	target   string
}

func newState(configFile string) *state {
	var e error
	cfg := createConfig(configFile)
	state := new(state)
	state.config = cfg
	config := api.DefaultConfig()
	config.Address = cfg.consulAddr
	state.consulClient, e = api.NewClient(config)
	if e != nil {
		LogError("Can't create consul client. Error ", e.Error())
	}
	if self, e := state.consulClient.Agent().Self(); e != nil {
		LogError("Can't connect to consul cluster. Error:", e.Error())
	} else {
		state.nodeDC = self["Config"]["Datacenter"].(string)
		state.nodeName = self["Config"]["NodeName"].(string)
	}
	state.nodeServices = make([]service, 0)
	return state
}

// do a refactoring

func (this *state) modifyLocalState() {
	localServices := this.config.getLocalServices()
	keys := make(map[string]*service)
	for idx, localService := range localServices {
		v := api.AgentServiceRegistration{
			Name: localService.ServiceName,
			Port: (int)(localService.ServicePort),
			Tags: []string{"local", "befw", (string)(localService.ServiceProtocol)},
		}
		if localService.ServicePorts != nil {
			for _, p := range localService.ServicePorts {
				v.Tags = append(v.Tags, p.toString())
			}
		}
		if e := this.consulClient.Agent().ServiceRegister(&v); e != nil {
			LogWarning(fmt.Sprintf("Can't register service %s @ %d/%s: %s",
				localService.ServiceName,
				localService.ServicePort,
				localService.ServiceProtocol, e.Error()))
		} else {
			LogInfo(fmt.Sprintf("Updating local service %s @ %d/%s", localService.ServiceName,
				localService.ServicePort, localService.ServiceProtocol))
			keys[localService.ServiceName] = &localServices[idx]
		}
	}
	// now deregister all 'local' services we has not
	if services, e := this.consulClient.Agent().Services(); e == nil {
		for key, consulService := range services {
			l, b := inArray(consulService.Tags, "local"), inArray(consulService.Tags, "befw")
			if !(l && b) { // non-local service
				continue
			}
			var proto befwServiceProto
			if inArray(consulService.Tags, "udp") {
				proto = ipprotoUdp
			} else {
				proto = ipprotoTcp
			}
			if sv, ok := keys[key]; !ok || !(sv.ServicePort == uint16(consulService.Port) && sv.ServiceProtocol == proto) {
				// deregister if has not same service
				if e := this.consulClient.Agent().ServiceDeregister(key); e == nil {
					LogInfo(fmt.Sprintf("Deregistering non-existing local service %s @ %d/%s", key, consulService.Port, proto))
				} else {
					LogWarning("Can't deregister local service ", key, ". Error: ", e.Error())
				}
			}
		}
	}
}

func inArray(arr []string, elem string) bool {
	for _, r := range arr {
		if r == elem {
			return true
		}
	}
	return false
}

func fromTags(tags []string) []port {
	result := make([]port, 0)
	newport := port{}
	for _, tag := range tags {
		test := strings.Split(tag, "/")
		if len(test) == 2 {
			if p, e := strconv.Atoi(test[0]); e == nil && p > 0 && p < 65535 {
				if test[1] == string(ipprotoTcp) || test[1] == string(ipprotoUdp) {
					newport.Port = p
					newport.PortProto = befwServiceProto(test[1])
					result = append(result, newport)
					newport = port{}
				}
			}
		}
	}
	return result
}

func (this *state) generateState() error {
	this.ipsets = this.config.getLocalIPSets()
	this.nodeServices = make([]service, 0)
	// download dynamic from consul
	// 2 download all services
	registeredServices, e := this.consulClient.Agent().Services()
	if e != nil {
		LogError("Can't download services information", e.Error())
		return e
	}
	for serviceName, serviceData := range registeredServices {
		if !isBefw(serviceData.Tags) {
			continue
		}
		newService := service{
			ServiceName:     serviceName,
			ServicePort:     uint16(serviceData.Port),
			ServiceProtocol: getProtocol(serviceData.Tags),
			serviceClients:  make([]serviceClient, 0),
			ServicePorts:    fromTags(serviceData.Tags),
		}
		// XXX: register BEFORE new service name
		newService.registerNflog()
		newServiceName := transform(&newService)
		this.ipsets[newServiceName] = make([]string, 0) // empty? ok!
		newService.ServiceName = newServiceName
		paths := this.generateKVPaths(newServiceName)

		// create ipset-newServiceName
		q := api.QueryOptions{Datacenter: this.config.consulDC}
		for _, path := range paths {
			pairs, _, e := this.consulClient.KV().List(path, &q)
			if e != nil {
				// error - consul unavailable, go out
				return e
			}
			for _, kvp := range pairs {
				if isAlias(kvp, path) {
					newService.serviceClients = append(newService.serviceClients, this.getAlias(kvp, path)...)
				} else {
					if kvp.Value == nil {
						continue
					}
					if newClient, e := kv2ServiceClient(kvp); e == nil {
						newService.serviceClients = append(newService.serviceClients, newClient)
					} else {
						LogWarning("Can't add service client", newServiceName, e.Error())
					}
				}
			}
		}
		this.nodeServices = append(this.nodeServices, newService)
	}
	// 3 ok let's append
	this.getAllowDenyIpsets()
	this.generateIPSets()
	return nil
}

func (this *state) applyState() error {
	// 4 we have to apply IPSET's and remove all unused
	for name, set := range this.ipsets {
		if y, e := applyIPSet(name, set); e != nil {
			LogWarning("Error while creating ipset", name, e.Error())
		} else if !y {
			LogWarning("create_ipset returned false", name)
		}
	}
	// 5. generate iptables rules
	if e := applyRules(this.generateRules()); e != nil {
		return e
	}
	// looks like we're ok
	LogInfo("BEFW refresh done:", len(this.nodeServices), "services,", len(this.ipsets), "ipsets")
	return nil

}

func refresh(configFile string) (*state, error) {
	state := newState(configFile)
	state.modifyLocalState()
	if err := state.generateState(); err != nil {
		LogWarning("Can't refresh state: ", err.Error())
		return nil, err
	}
	if err := state.applyState(); err != nil {
		LogWarning("Can't apply state: ", err.Error())
		return state, err
	}

	return state, nil
}

func showState(configFile string) (data map[string][]string, e error) {
	data = make(map[string][]string)
	e = nil
	state := newState(configFile)
	if err := state.generateState(); err != nil {
		LogWarning("Can't refresh state: ", err.Error())
		e = err
		return
	}
	for _, srv := range state.nodeServices {
		data[srv.ServiceName] = state.ipsets[srv.ServiceName]
		data["*NodeName"] = []string{state.nodeName}
		data["*NodeDC"] = []string{state.nodeDC}
	}
	return
}

func isAlias(pair *api.KVPair, path string) bool {
	aliasName := strings.Replace(pair.Key, path, "", 1)
	if strings.HasPrefix(aliasName, "$") &&
		strings.HasSuffix(aliasName, "$") {
		return true
	}
	return false
}

func (this *state) getAlias(pair *api.KVPair, path string) []serviceClient {
	aliasName := strings.Replace(pair.Key, path, "", 1)
	q := api.QueryOptions{Datacenter: this.config.consulDC}
	path = fmt.Sprintf("befw/$alias$/%s/", aliasName)
	res := make([]serviceClient, 0)
	if pairs, _, e := this.consulClient.KV().List(path, &q); e == nil {
		for _, kvp := range pairs {
			if kvp.Value == nil {
				continue
			}
			if newClient, e := kv2ServiceClient(kvp); e == nil {
				res = append(res, newClient)
			}
		}
	}
	return res
}
func kv2ServiceClient(pair *api.KVPair) (serviceClient, error) {
	var expiryTime int64
	result := serviceClient{}
	client := path2ipnet(pair.Key)
	if client == nil {
		return result, errors.New("Bad CIDR: " + pair.Key)
	}
	result.clientCIDR = client
	expiryTime, e := strconv.ParseInt(string(pair.Value), 10, 64)
	if e != nil { // invalid values never expires for safety reasons
		expiryTime = time.Now().Unix() + 3600 // +1 h
	}
	result.clientExpiry = expiryTime
	return result, nil
}

func (this *state) generateKVPaths(newServiceName string) []string {
	return []string{
		fmt.Sprintf("befw/%s/%s/%s/", this.nodeDC, this.nodeName, newServiceName),
		fmt.Sprintf("befw/%s/%s/", this.nodeDC, newServiceName),
		fmt.Sprintf("befw/%s/", newServiceName),
	}
}

func (this *state) getAllowDenyIpsets() {
	q := api.QueryOptions{Datacenter: this.config.consulDC}
	for _, set := range this.config.setList {
		for _, path := range this.generateKVPaths(set.name) {
			pairs, _, e := this.consulClient.KV().List(path, &q)
			if e != nil {
				LogWarning("Can't obtain data from kv:", path, e.Error())
				continue
			}
			for _, kvp := range pairs {
				if isAlias(kvp, path) {
					for _, newClient := range this.getAlias(kvp, path) {
						newClient.appendToIpsetIf(&this.ipsets, set.name)
					}
				} else {
					if newClient, e := kv2ServiceClient(kvp); e == nil {
						newClient.appendToIpsetIf(&this.ipsets, set.name)
					} else {
						LogWarning("Can't add pre-defined ipset", set, e.Error())
					}
				}

			}
		}
	}
}

func (this *serviceClient) appendToIpsetIf(ipsets *map[string][]string, ipset string) {
	if !this.isExpired() {
		if (*ipsets)[ipset] == nil {
			(*ipsets)[ipset] = make([]string, 0)
		}
		(*ipsets)[ipset] = append((*ipsets)[ipset], this.clientCIDR.String())
	}
}
func (this *serviceClient) isExpired() bool {
	epoch := time.Now().Unix()
	if this.clientExpiry < 0 || this.clientExpiry > epoch {
		return false
	}
	return true
}

func (this *state) generateIPSets() {
	for _, localService := range this.nodeServices {
		for _, c := range localService.serviceClients {
			c.appendToIpsetIf(&this.ipsets, localService.ServiceName)
		}
	}
}

func transform(srv *service) string {
	serviceName := srv.ServiceName
	// 1. lower
	serviceName = strings.ToLower(serviceName)
	// 2. remove all non-FQDN symbols
	tmp := strings.Builder{}
	for _, v := range []byte(serviceName) {
		if v >= 'A' && v <= 'Z' {
			tmp.WriteByte(v)
		} else if v >= 'a' && v <= 'z' {
			tmp.WriteByte(v)
		} else if v >= '0' && v <= '9' {
			tmp.WriteByte(v)
		} else if v == '-' || v == '.' || v == '_' {
			tmp.WriteByte(v)
		}
	}
	// 3. add protocol_port_ to the end
	tmp.WriteByte('_')
	tmp.WriteString(string(srv.ServiceProtocol))
	tmp.WriteByte('_')
	tmp.WriteString(strconv.Itoa(int(srv.ServicePort)))
	return tmp.String()
}

func isBefw(tags []string) bool {
	for _, r := range tags {
		if r == "befw" {
			return true
		}
	}
	return false
}

func getProtocol(tags []string) befwServiceProto {
	for _, r := range tags {
		if r == "tcp" {
			return ipprotoTcp
		}
		if r == "udp" {
			return ipprotoUdp
		}
	}
	return ipprotoTcp // default is TCP
}

func RegisterService(configFile, name, protocol string, port int) error {
	if port < 1 || port > 65535 {
		return errors.New("port must be in (1..65535)")
	}
	if !(protocol == "tcp" || protocol == "udp") {
		return errors.New("protocol must be in (tcp,udp)")
	}
	state := newState(configFile)
	if services, e := state.consulClient.Agent().Services(); e == nil {
		for k, v := range services {
			if name == k {
				return errors.New("this name already exists")
			}
			var proto befwServiceProto
			if inArray(v.Tags, "udp") {
				proto = ipprotoUdp
			} else {
				proto = ipprotoTcp
			}
			if port == v.Port && string(proto) == protocol {
				return errors.New(fmt.Sprintf("this port/protocol pair already exists with name %s", k))
			}
		}
		if e := state.consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
			Name: name,
			Port: port,
			Tags: []string{"befw", protocol},
		}); e == nil {
			return nil
		} else {
			return e
		}
	} else {
		return e
	}
}

func DeregisterService(configFile, name string) error {
	state := newState(configFile)
	if services, e := state.consulClient.Agent().Services(); e == nil {
		if v, ok := services[name]; !ok {
			return errors.New(fmt.Sprintf("service %s not found on local agent", name))
		} else if !inArray(v.Tags, "befw") {
			return errors.New("this service is not befw-tagged service")
		} else if inArray(v.Tags, "local") {
			return errors.New("this service is defined via puppet, please use puppet to disable it")
		} else {
			if e := state.consulClient.Agent().ServiceDeregister(name); e != nil {
				return e
			} else {
				return nil
			}
		}
	} else {
		return e
	}
}
