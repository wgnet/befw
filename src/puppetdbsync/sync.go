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
package puppetdbsync

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/hashicorp/consul/api"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)
import "../befw"

func newSync(config string) *syncConfig {
	conf := &syncConfig{
		services:      make(map[string]int64),
		servicesMutex: new(sync.RWMutex),
		servicesWG:    new(sync.WaitGroup),
		lastResult:    make([]string, 0),
		lastCounter:   0,
		timeout:       10 * time.Second, //default
	}
	if x, e := os.Stat(config); e != nil {
		befw.LogError("[Syncer] Can't get config from ", config, ": ", e.Error())
		return nil
	} else if x.IsDir() {
		befw.LogError("[Syncer] Config file is a directory: ", config)
		return nil
	}
	kv := make(map[string]string)
	if f, e := os.Open(config); e != nil {
		befw.LogError("[Syncer] Can't open config file ", config, ": ", e.Error())
		return nil
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
			conf.consulAddr = v
		}
		if v, ok := kv["dc"]; ok {
			conf.consulDC = v
		}
		if v, ok := kv["url"]; ok {
			conf.url = v
		}
		if v, ok := kv["verify"]; ok {
			conf.verify = strings.ToLower(v) == "true" || strings.ToLower(v) == "yes"
		}
		if v, ok := kv["token"]; ok {
			conf.commitToken = v
		}
	}
	conf.httpClient = &http.Client{}
	if !conf.verify {
		trans := *(http.DefaultTransport.(*http.Transport))
		trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		conf.httpClient.Transport = &trans
	}
	consulConfig := api.DefaultConfig()
	if conf.consulAddr != "" {
		consulConfig.Address = conf.consulAddr
	}
	if conf.commitToken != "" {
		consulConfig.Token = conf.commitToken
	}
	if conf.consulDC != "" {
		consulConfig.Datacenter = conf.consulDC
	}
	var e error
	if conf.consulClient, e = api.NewClient(consulConfig); e != nil {
		befw.LogError("[Syncer] Invalid Consul config: ", e.Error())
		return nil
	}
	if self, e := conf.consulClient.Agent().Self(); e != nil {
		befw.LogError("[Syncer] Can't connect to Consul: ", e.Error())
		return nil
	} else {
		conf.nodeName = self["Config"]["NodeName"].(string)
		conf.nodeAddr = self["Member"]["Addr"].(string)
	}
	return conf
}

func (conf *syncConfig) makeHotCache() {
	if conf.cache == nil { // first time
		conf.cache = new(hotCache)
		conf.cache.dcs = make(map[string]interface{})
		conf.cache.nodes = make(map[string]interface{})
		conf.cacheMutex = new(sync.RWMutex)
	}
	conf.cache.error = false
	conf.cacheMutex.Lock()
	defer conf.cacheMutex.Unlock()
	if dcs, e := conf.consulClient.Catalog().Datacenters(); e != nil {
		conf.cache.error = true
		return
	} else {
		for dc, _ := range conf.cache.dcs {
			delete(conf.cache.dcs, dc)
		}
		for _, dc := range dcs {
			conf.cache.dcs[dc] = nil
		}
	}
	for node, _ := range conf.cache.nodes {
		delete(conf.cache.nodes, node)
	}
	for dc, _ := range conf.cache.dcs {
		q := &api.QueryOptions{
			Datacenter: dc,
		}
		if nodes, _, e := conf.consulClient.Catalog().Nodes(q); e != nil {
			conf.cache.error = true
			return
		} else {
			for _, node := range nodes {
				nodeName := strings.Split(node.Node, ".")[0]
				conf.cache.nodes[dc+"@"+nodeName] = nil
			}
		}
	}
	befw.LogDebug(fmt.Sprintf("[Syncer] Cache updated: %d datacenters, %d nodes",
		len(conf.cache.dcs), len(conf.cache.nodes)))
}

func (conf *syncConfig) writeSyncData(data *syncData) {
	conf.servicesMutex.Lock()
	defer conf.servicesMutex.Unlock()
	defer conf.servicesWG.Done()
	path := fmt.Sprintf("%s/%s", data.service, data.value)
	if data.node != "" {
		path = fmt.Sprintf("%s/%s", data.node, path)
	}
	if data.dc != "" {
		path = fmt.Sprintf("%s/%s", data.dc, path)
	}
	path = fmt.Sprintf("befw/$service$/%s", path)
	value := time.Now().Unix() + 1209600 // 2 weeks

	if v, ok := conf.services[path]; !(ok && v > time.Now().Unix()) {
		_, e := conf.consulClient.KV().Put(&api.KVPair{
			Key:   path,
			Value: []byte(fmt.Sprintf("%d", value)),
		}, nil)
		if e != nil {
			befw.LogWarning("[Syncer] can't write data to KV: ", path, ":", e.Error())
		}
		conf.services[path] = value
		befw.LogInfo("[Syncer] wrote ", path, "to KV with value ", value)
	}
}

func (conf *syncConfig) manageSession() {
	//nodeName := fmt.Sprintf("%s.%s", conf.consulDC, conf.nodeName)
	errcount := 0
	for errcount < 10 {
		//// 1. register main node
		if _, e := conf.consulClient.Catalog().Register(&api.CatalogRegistration{
			Node:       conf.nodeName,
			Address:    conf.nodeAddr,
			Datacenter: conf.consulDC,
		}, nil); e != nil {
			befw.LogWarning("[Syncer] can't register a node!")
		}
		befw.LogDebug("[Syncer] starting session creation")
		if conf.sessionID == "" {
			if sess, _, e := conf.consulClient.Session().CreateNoChecks(
				&api.SessionEntry{
					Node: conf.nodeName,
					Name: "befw-sync",
					TTL:  "40s",
				}, &api.WriteOptions{Datacenter: conf.consulDC}); e == nil {
				conf.sessionID = sess
			} else {
				befw.LogWarning("[Syncer] Can't create session: ", e.Error())
				errcount++
				continue
			}
		} else {
			if se, _, e := conf.consulClient.Session().Info(conf.sessionID, nil); e != nil {
				conf.sessionID = ""
				befw.LogDebug("[Syncer] error while getting session: ", conf.sessionID, ", ", e.Error())
				errcount++
				continue
			} else if se == nil {
				conf.sessionID = ""
				befw.LogDebug("[Syncer] Can't find session:", conf.sessionID)
				errcount++
				continue
			}
			if se, _, e := conf.consulClient.Session().Renew(conf.sessionID, nil); e != nil {
				conf.sessionID = ""
				befw.LogDebug("[Syncer] error while renewning session: ", conf.sessionID, ", ", e.Error())
				errcount++
				continue
			} else if se == nil {
				conf.sessionID = ""
				befw.LogDebug("[Syncer] Can't find session:", conf.sessionID)
				errcount++
				continue
			}
		}
		break
	}
	befw.LogDebug("[Syncer] got session ", conf.sessionID)
}

func (conf *syncConfig) getSessionHolder(session string) string {
	if se, _, e := conf.consulClient.Session().Info(session, nil); e == nil && se != nil {
		return fmt.Sprintf("%s@%s", se.Name, se.Node)
	}
	return ""
}

var lastState bool

func (conf *syncConfig) manageSessionLock() bool {
	conf.manageSession()
	if conf.sessionID != "" {
		if v, _, e := conf.consulClient.KV().Acquire(
			&api.KVPair{Key: "befw/.lock",
				Value:   []byte(conf.nodeName),
				Session: conf.sessionID,
			}, &api.WriteOptions{Datacenter: conf.consulDC}); e != nil {
			befw.LogWarning("[Syncer] Can't create lock:", e.Error())
			return false
		} else {
			if !v {
				if kv, _, e := conf.consulClient.KV().Get("befw/.lock", nil); e == nil {
					if kv.Session != "" {
						if si := conf.getSessionHolder(kv.Session); si != "" {
							befw.LogInfo("[Syncer] key is locked by ", si)
						}
					}
				}
			} else {
				befw.LogInfo("[Syncer] Lock acquired by me")
			}
			return v
		}
	}
	return false
}

func (conf *syncConfig) cleanup() {
	nodeName := fmt.Sprintf("%s.%s", conf.consulDC, conf.nodeName)
	conf.consulClient.Catalog().Deregister(&api.CatalogDeregistration{
		Node:       nodeName,
		Address:    conf.nodeAddr,
		Datacenter: conf.consulDC,
	}, nil)

}
