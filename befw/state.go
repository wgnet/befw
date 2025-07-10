/**
 * Copyright 2018-2023 Wargaming Group Limited
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
	NodeServices        []bService
	StaticIPSets        map[string][]string
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
	state.NodeServices = make([]bService, 0)
	return state
}

// do a refactoring

func (state *state) modifyLocalState() {
	localServices := state.Config.getLocalServices()
	keys := make(map[string]bService)
	for _, localService := range localServices {
		if len(localService.Ports) <= 0 {
			logging.LogWarning(fmt.Sprintf("Skip service %s: no ports", localService.Name))
			continue
		}
		first := localService.Ports[0]
		v := api.AgentServiceRegistration{
			Name: localService.Name,
			Port: int(first.From),
			Tags: []string{"local", "befw", (string)(first.Protocol), localService.Mode.asTag()},
		}
		for _, p := range localService.Ports {
			v.Tags = append(v.Tags, p.toTag())
		}
		if e := state.consulClient.Agent().ServiceRegister(&v); e != nil {
			logging.LogWarning(fmt.Sprintf("Can't register service %s: %s",
				localService.Name, e.Error()))
		} else {
			logging.LogDebug(fmt.Sprintf("Updating local service %s", localService.Name))
			keys[localService.Name] = localService
		}
	}
	// now deregister all 'local' services we has not
	if services, e := state.consulClient.Agent().Services(); e == nil {
		for key, consulService := range services {
			l, b := inArray(consulService.Tags, "local"), inArray(consulService.Tags, "befw")
			if !(l && b) { // non-local service
				continue
			}
			var prot netProtocol
			if inArray(consulService.Tags, "udp") {
				prot = PROTOCOL_UDP
			} else {
				prot = PROTOCOL_TCP
			}
			if sv, ok := keys[key]; !ok ||
				len(sv.Ports) <= 0 ||
				!(sv.Ports[0].From == uint16(consulService.Port) && sv.Ports[0].Protocol == prot) {
				// deregister if has not same service
				if e := state.consulClient.Agent().ServiceDeregister(key); e == nil {
					logging.LogInfo(fmt.Sprintf("Deregistering non-existing local service %s", key))
				} else {
					logging.LogWarning("Can't deregister local service ", key, ". Error: ", e.Error())
				}
			}
		}
	}
}

func fromTags(portNum uint16, tags []string) []bPort {
	result := make([]bPort, 0)
	for _, tag := range tags {
		newport, err := NewBPort(tag)
		if err != nil {
			continue
		}
		result = append(result, *newport)
	}
	return result
}

func (state *state) generateState() error {
	state.StaticIPSets = state.Config.getLocalIPSets()
	state.NodeServices = make([]bService, 0)
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
		newService := bService{
			Name:    serviceName,
			Mode:    getModeFromTags(serviceData.Tags),
			Clients: make([]bClient, 0),
			Ports:   fromTags(uint16(serviceData.Port), serviceData.Tags),
		}
		// XXX: register BEFORE new service Name
		newService.nflogRegister()
		newServiceName := transform(&newService)
		state.StaticIPSets[newServiceName] = make([]string, 0) // empty? ok!
		newService.Name = newServiceName
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
					if isAliasPath(kvp, path) {
						if alias, e := state.getAlias(kvp, path); e != nil {
							logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
							return e
						} else {
							newService.Clients = append(newService.Clients, alias...)
						}
					} else {
						if kvp.Value == nil {
							continue
						}
						if newClient, e := kv2ServiceClient(kvp); e == nil {
							newService.Clients = append(newService.Clients, newClient)
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
	if e := state.fillStaticIPSets(); e != nil {
		return e
	}
	return nil
}

func refresh(configFile string) (retState *state, retError error) {
	var state *state
	// drop old aliases:
	aliasResolver.Clear()
	defer func() {
		if e := recover(); e != nil {
			// DISASTER RECOVERY
			logging.LogWarning("[BEFW] Recovering from error: ", e)
			state = recoverLastState(configFile)
			state.fillMandatoryIPSet()
			err := fw.Apply(state)
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
	if err := fw.Apply(state); err != nil {
		logging.LogWarning("Can't apply state: ", err.Error())
		return state, err
	}
	state.saveLastState() // always
	logging.LogDebug("Refresh done")
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
		data[srv.Name] = state.StaticIPSets[srv.Name]
		data["*NodeName"] = []string{state.nodeName}
		data["*NodeDC"] = []string{state.nodeDC}
	}
	return
}

func isAliasPath(pair *api.KVPair, path string) bool {
	return isAlias(strings.Replace(pair.Key, path, "", 1))
}

func (state *state) getAlias(pair *api.KVPair, path string) ([]bClient, error) {
	aliasName := strings.Replace(pair.Key, path, "", 1)
	// Resolve Alias:
	aliasResolver.updater = state.consulAlias
	nets := aliasResolver.Resolve(aliasName)

	result := make([]bClient, 0)
	for _, netstr := range nets {
		if _, cidr, e := net.ParseCIDR(netstr); e == nil && cidr != nil {
			expiryTime, e := strconv.ParseInt(string(pair.Value), 10, 64)
			if e != nil { // invalid values never expires for safety reasons
				expiryTime = time.Now().Unix() + 3600 // +1 h
			}
			client := bClient{
				CIDR:   cidr,
				Expiry: expiryTime,
			}
			result = append(result, client)
		}
	}
	return result, nil
}

func kv2ServiceClient(pair *api.KVPair) (bClient, error) {
	var expiryTime int64
	result := bClient{}
	client := path2ipnet(pair.Key)
	if client == nil {
		return result, errors.New("Bad CIDR: " + pair.Key)
	}
	result.CIDR = client
	expiryTime, e := strconv.ParseInt(string(pair.Value), 10, 64)
	if e != nil { // invalid values never expires for safety reasons
		expiryTime = time.Now().Unix() + 3600 // +1 h
	}
	result.Expiry = expiryTime
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

func (state *state) fillStaticIPSets() error {
	for _, set := range state.Config.StaticSetList {
		state.StaticIPSets[set.Name] = make([]string, 0) // empty? ok!
		for _, path := range state.generateIPSetKVPaths(set.Name) {
			if kvs, e := state.consulKVList(path); e != nil {
				logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
				return e
			} else {
				for _, kvp := range kvs {
					if isAliasPath(kvp, path) {
						if alias, e := state.getAlias(kvp, path); e != nil {
							logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
							return e
						} else {
							for _, newClient := range alias {
								newClient.appendToIpsetIf(&state.StaticIPSets, set.Name)
							}
						}
					} else {
						if newClient, e := kv2ServiceClient(kvp); e == nil {
							newClient.appendToIpsetIf(&state.StaticIPSets, set.Name)
						} else {
							logging.LogWarning("Can't add pre-defined ipset ", set, ": ", e.Error())
						}
					}

				}
			}
		}
	}
	return nil
}

func (this *bClient) appendToIpsetIf(ipsets *map[string][]string, ipset string) {
	if !this.isExpired() {
		if (*ipsets)[ipset] == nil {
			(*ipsets)[ipset] = make([]string, 0)
		}
		(*ipsets)[ipset] = append((*ipsets)[ipset], this.CIDR.String())
	}
}

func transform(srv *bService) string {
	serviceName := srv.Name
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
	// 3. add protocol_port_ to the end from first port
	if len(srv.Ports) <= 0 {
		logging.LogWarning(fmt.Sprintf("Strange service %s: no ports", srv.Name))
		tmp.WriteString("") // Don't use ports in registration name.
		return tmp.String()
	}
	first := srv.Ports[0]
	tmp.WriteByte('_')
	tmp.WriteString(first.Protocol)
	tmp.WriteByte('_')
	tmp.WriteString(fmt.Sprint(first.From))
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
			// Legacy tags support
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

func (state *state) fillMandatoryIPSet() {
	if state.StaticIPSets == nil {
		state.StaticIPSets = make(map[string][]string)
	}
	for _, conf := range staticIPSetList {
		if _, ok := state.StaticIPSets[conf.Name]; !ok {
			state.StaticIPSets[conf.Name] = make([]string, 0)
		}

	}
	state.StaticIPSets[SET_ALLOW] = append(state.StaticIPSets[SET_ALLOW], mandatoryIPSet...)
	if state.Config == nil || state.Config.MandatoryIPSet == nil {
		return
	}
	state.StaticIPSets[SET_ALLOW] = append(state.StaticIPSets[SET_ALLOW], state.Config.MandatoryIPSet...)
}
