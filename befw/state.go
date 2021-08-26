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
	"errors"
	"fmt"
	"github.com/hashicorp/consul/api"
	"github.com/wgnet/befw/logging"
	"net"
	"strconv"
	"strings"
	"time"
)

type state struct {
	consulClient        *api.Client
	consulWatcherClient *api.Client
	nodeName            string
	nodeDC              string
	localDC             string
	NodeServices        []service
	IPSets              map[string][]string
	lastUpdated         time.Time
	Config              *config
}

type ipset struct {
	name   string
	ipList []*net.IPNet
}

type staticIPSetConf struct {
	Name     string
	Priority int
	Target   string
}

func newState(configFile string) *state {
	var e error
	cfg := createConfig(configFile)
	cfg.createStaticIPSets() // before any
	state := new(state)
	state.Config = cfg

	consulConfig := api.DefaultNonPooledConfig()
	consulConfig.Address = cfg.ConsulAddr
	if cfg.ConsulToken != "" {
		consulConfig.Token = cfg.ConsulToken
	}
	state.consulClient, e = api.NewClient(consulConfig)
	// XXX: now we have client

	consulConfig.HttpClient.Timeout = state.Config.Timeout.Consul

	consulWatcherConfig := api.DefaultConfig()
	consulWatcherConfig.Address = cfg.ConsulAddr
	if cfg.ConsulToken != "" {
		consulWatcherConfig.Token = cfg.ConsulToken
	}
	state.consulWatcherClient, e = api.NewClient(consulWatcherConfig)
	consulWatcherConfig.HttpClient.Timeout = state.Config.Timeout.ConsulWatch
	// watcher client
	if e != nil {
		logging.LogError("Can't create consul client. Error ", e.Error())
	}
	if self, e := state.consulClient.Agent().Self(); e != nil {
		logging.LogError("Can't connect to consul cluster. Error:", e.Error())
	} else {
		if cfg.NodeDC != "" {
			state.nodeDC = cfg.NodeDC
		} else {
			state.nodeDC = self["Config"]["Datacenter"].(string)
		}
		if cfg.NodeName != "" {
			state.nodeName = cfg.NodeName
		} else {
			state.nodeName = self["Config"]["NodeName"].(string)
		}
		state.nodeDC = strings.ToLower(state.nodeDC)
		state.nodeName = strings.ToLower(strings.Split(state.nodeName, ".")[0])
	}
	state.localDC = state.nodeName
	// cut first -
	for i := 0; i < len(state.localDC); i++ {
		if state.localDC[i] == '-' {
			state.localDC = state.localDC[:i]
			break
		}
	}
	state.NodeServices = make([]service, 0)
	return state
}

// do a refactoring

func (state *state) modifyLocalState() {
	localServices := state.Config.getLocalServices()
	keys := make(map[string]*service)
	for idx, localService := range localServices {
		v := api.AgentServiceRegistration{
			Name: localService.ServiceName,
			Port: (int)(localService.ServicePort),
			Tags: []string{"local", "befw", (string)(localService.ServiceProtocol), localService.ServiceMode},
		}
		if localService.ServicePorts != nil {
			for _, p := range localService.ServicePorts {
				v.Tags = append(v.Tags, p.toTag())
			}
		}
		if e := state.consulClient.Agent().ServiceRegister(&v); e != nil {
			logging.LogWarning(fmt.Sprintf("Can't register service %s @ %d/%s: %s",
				localService.ServiceName,
				localService.ServicePort,
				localService.ServiceProtocol, e.Error()))
		} else {
			logging.LogInfo(fmt.Sprintf("Updating local service %s @ %d/%s", localService.ServiceName,
				localService.ServicePort, localService.ServiceProtocol))
			keys[localService.ServiceName] = &localServices[idx]
		}
	}
	// now deregister all 'local' services we has not
	if services, e := state.consulClient.Agent().Services(); e == nil {
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
				if e := state.consulClient.Agent().ServiceDeregister(key); e == nil {
					logging.LogInfo(fmt.Sprintf("Deregistering non-existing local service %s @ %d/%s", key, consulService.Port, proto))
				} else {
					logging.LogWarning("Can't deregister local service ", key, ". Error: ", e.Error())
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

func fromTags(tags []string) []befwPort {
	result := make([]befwPort, 0)
	for _, tag := range tags {
		newport, err := PortFromTag(tag)
		if err != nil {continue}
		result = append(result, *newport)
	}
	return result
}

func (state *state) generateState() error {
	state.IPSets = state.Config.getLocalIPSets()
	state.NodeServices = make([]service, 0)
	// download dynamic from consul
	// 2 download all services
	registeredServices, e := state.consulClient.Agent().Services()
	if e != nil {
		logging.LogError("Can't download services information", e.Error())
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
			ServiceMode:     getMode(serviceData.Tags),
			serviceClients:  make([]serviceClient, 0),
			ServicePorts:    fromTags(serviceData.Tags),
		}
		// XXX: register BEFORE new service Name
		newService.registerNflog()
		newServiceName := transform(&newService)
		state.IPSets[newServiceName] = make([]string, 0) // empty? ok!
		newService.ServiceName = newServiceName
		paths := state.generateKVPaths(newServiceName)

		// create ipset-newServiceName
		for _, path := range paths {
			if kvs, e := state.consulKVList(path); e != nil {
				logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
				return e
			} else {
				for _, kvp := range kvs {
					if !BEFWRegexp.MatchString(kvp.Key) {
						continue // do not fucking try
					}
					if isAlias(kvp, path) {
						if alias, e := state.getAlias(kvp, path); e != nil {
							logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
							return e
						} else {
							newService.serviceClients = append(newService.serviceClients, alias...)
						}
					} else {
						if kvp.Value == nil {
							continue
						}
						if newClient, e := kv2ServiceClient(kvp); e == nil {
							newService.serviceClients = append(newService.serviceClients, newClient)
						} else {
							logging.LogWarning("Can't add service client", newServiceName, e.Error())
						}
					}
				}
			}
		}
		state.NodeServices = append(state.NodeServices, newService)
	}
	// 3 ok let's append
	if e := state.getStaticIPSets(); e != nil {
		return e
	}
	state.generateIPSets()
	return nil
}

func (state *state) applyState() error {
	lastContentLock.Lock()
	defer lastContentLock.Unlock()
	// begin old rules cleanup
	for k := range lastIPSetContent {
		delete(lastIPSetContent, k)
	}
	lastIPTablesContent = ""
	// end old rules cleanup

	// 4 we have to apply IPSET's and remove all unused
	for name, set := range state.IPSets {
		if y, e := applyIPSet(name, set); e != nil {
			logging.LogWarning("Error while creating ipset", name, e.Error())
			return e
		} else if !y {
			logging.LogWarning("create_ipset returned false", name)
			return errors.New("create_ipset returned false")
		}
	}
	// 5. generate iptables rules
	if e := applyRules(state.generateRules()); e != nil {
		return e
	}
	// looks like we're ok
	logging.LogInfo("BEFW refresh done: ", len(state.NodeServices), "services, ", len(state.IPSets), "IPSets")
	return nil

}

var aliasCache map[string][]serviceClient

func refresh(configFile string) (retState *state, retError error) {
	var state *state
	aliasCache = make(map[string][]serviceClient) // drop old aliases
	defer func() {
		if e := recover(); e != nil {
			logging.LogWarning("[BEFW] Recovering from error: ", e)
			state = recoverLastState(configFile)
			state.applyWhitelistIPSet()
			err := state.applyState()
			if err != nil {
				logging.LogWarning("[BEFW] Error recovering last state: ", err.Error())
			}
			retState = state
			retError = errors.New("recovered from panic")
		}
	}()
	state = newState(configFile)
	state.modifyLocalState()
	if err := state.generateState(); err != nil {
		logging.LogWarning("Can't refresh state: ", err.Error())
		return nil, err
	}
	//state.applyWhitelistIPSet()
	if err := state.applyState(); err != nil {
		logging.LogWarning("Can't apply state: ", err.Error())
		return state, err
	}
	state.saveLastState() // always
	return state, nil
}

func showState(configFile string) (data map[string][]string, e error) {
	data = make(map[string][]string)
	e = nil
	state := newState(configFile)
	if err := state.generateState(); err != nil {
		logging.LogWarning("Can't refresh state: ", err.Error())
		e = err
		return
	}
	for _, srv := range state.NodeServices {
		data[srv.ServiceName] = state.IPSets[srv.ServiceName]
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

func (state *state) getAlias(pair *api.KVPair, path string) ([]serviceClient, error) {
	if aliasCache == nil {
		aliasCache = make(map[string][]serviceClient)
	}
	aliasName := strings.Replace(pair.Key, path, "", 1)
	if v, ok := aliasCache[aliasName]; ok {
		return v, nil
	}
	path = fmt.Sprintf("befw/$alias$/%s/", aliasName)
	res := make([]serviceClient, 0)
	if kvs, e := state.consulKVList(path); e != nil {
		return nil, e
	} else {
		for _, kvp := range kvs {
			if kvp.Value == nil {
				continue
			}
			if newClient, e := kv2ServiceClient(kvp); e == nil {
				res = append(res, newClient)
			}
		}
		aliasCache[aliasName] = res
		return res, nil
	}
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

func (state *state) generateKVPaths(newServiceName string) []string {
	ret := []string{
		fmt.Sprintf("befw/$service$/%s/%s/%s/", state.nodeDC, state.nodeName, newServiceName),
		fmt.Sprintf("befw/$service$/%s/%s/", state.nodeDC, newServiceName),
		fmt.Sprintf("befw/$service$/%s/", newServiceName),
		fmt.Sprintf("befw/$service$/%s/%s/%s/", state.localDC, state.nodeName, newServiceName),
		fmt.Sprintf("befw/$service$/%s/%s/", state.localDC, newServiceName),
	}
	return ret
}

func (state *state) generateIPSetKVPaths(ipsetName string) []string {
	ret := []string{
		fmt.Sprintf("befw/$ipset$/%s/%s/%s/", state.nodeDC, state.nodeName, ipsetName),
		fmt.Sprintf("befw/$ipset$/%s/%s/", state.nodeDC, ipsetName),
		fmt.Sprintf("befw/$ipset$/%s/", ipsetName),
		fmt.Sprintf("befw/$ipset$/%s/%s/%s/", state.localDC, state.nodeName, ipsetName),
		fmt.Sprintf("befw/$ipset$/%s/%s/", state.localDC, ipsetName),
	}
	return ret
}

func (state *state) consulKVList(prefix string) (api.KVPairs, error) {

	queryOptions := &api.QueryOptions{
		Datacenter:        state.Config.ConsulDC,
		UseCache:          false,
		AllowStale:        true,
		RequireConsistent: false,
	}
	if r, _, e := state.consulClient.KV().List(prefix, queryOptions); e == nil {
		return r, e
	} else {
		return nil, e
	}
}

func (state *state) getStaticIPSets() error {
	for _, set := range state.Config.StaticSetList {
		state.IPSets[set.Name] = make([]string, 0) // empty? ok!
		for _, path := range state.generateIPSetKVPaths(set.Name) {
			if kvs, e := state.consulKVList(path); e != nil {
				logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
				return e
			} else {
				for _, kvp := range kvs {
					if isAlias(kvp, path) {
						if alias, e := state.getAlias(kvp, path); e != nil {
							logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
							return e
						} else {
							for _, newClient := range alias {
								newClient.appendToIpsetIf(&state.IPSets, set.Name)
							}
						}
					} else {
						if newClient, e := kv2ServiceClient(kvp); e == nil {
							newClient.appendToIpsetIf(&state.IPSets, set.Name)
						} else {
							logging.LogWarning("Can't add pre-defined ipset", set, e.Error())
						}
					}

				}
			}
		}
	}
	return nil
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

func (state *state) generateIPSets() {
	for _, localService := range state.NodeServices {
		for _, c := range localService.serviceClients {
			c.appendToIpsetIf(&state.IPSets, localService.ServiceName)
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

func getMode(tags []string) string {
	for _, r := range tags {
		if r == "enforcing" {
			return "enforcing"
		}
	}
	return "default"
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
				return errors.New("this Name already exists")
			}
			var proto befwServiceProto
			if inArray(v.Tags, "udp") {
				proto = ipprotoUdp
			} else {
				proto = ipprotoTcp
			}
			if port == v.Port && string(proto) == protocol {
				return errors.New(fmt.Sprintf("this port/protocol pair already exists with Name %s", k))
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

func (state *state) applyWhitelistIPSet() {
	if state.IPSets == nil {
		state.IPSets = make(map[string][]string)
	}
	for _, conf := range staticIPSetList {
		if _, ok := state.IPSets[conf.Name]; !ok {
			state.IPSets[conf.Name] = make([]string, 0)
		}

	}
	state.IPSets[allowIPSetName] = append(state.IPSets[allowIPSetName], mandatoryIPSet...)
	if state.Config == nil || state.Config.WhitelistIPSet == nil {
		return
	}
	state.IPSets[allowIPSetName] = append(state.IPSets[allowIPSetName], state.Config.WhitelistIPSet...)
}
