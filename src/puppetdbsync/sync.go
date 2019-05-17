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

func (this *syncConfig) makeHotCache() {
	if this.cache == nil { // first time
		this.cache = new(hotCache)
		this.cache.dcs = make(map[string]interface{})
		this.cache.nodes = make(map[string]interface{})
		this.cacheMutex = new(sync.RWMutex)
	}
	this.cache.error = false
	this.cacheMutex.Lock()
	defer this.cacheMutex.Unlock()
	if dcs, e := this.consulClient.Catalog().Datacenters(); e != nil {
		this.cache.error = true
		return
	} else {
		for dc, _ := range this.cache.dcs {
			delete(this.cache.dcs, dc)
		}
		for _, dc := range dcs {
			this.cache.dcs[dc] = nil
		}
	}
	for node, _ := range this.cache.nodes {
		delete(this.cache.nodes, node)
	}
	for dc, _ := range this.cache.dcs {
		q := &api.QueryOptions{
			Datacenter: dc,
		}
		if nodes, _, e := this.consulClient.Catalog().Nodes(q); e != nil {
			this.cache.error = true
			return
		} else {
			for _, node := range nodes {
				this.cache.nodes[dc+"@"+node.Node] = nil
			}
		}
	}
	befw.LogInfo(fmt.Sprintf("[Syncer] Cache updated: %d datacenters, %d nodes",
		len(this.cache.dcs), len(this.cache.nodes)))
}

func (this *syncConfig) writeSyncData(data *syncData) {
	this.servicesMutex.Lock()
	defer this.servicesMutex.Unlock()
	defer this.servicesWG.Done()
	path := fmt.Sprintf("%s/%s", data.service, data.value)
	if data.node != "" {
		path = fmt.Sprintf("%s/%s", data.node, path)
	}
	if data.dc != "" {
		path = fmt.Sprintf("%s/%s", data.dc, path)
	}
	path = fmt.Sprintf("befw/%s", path)
	value := time.Now().Unix() + 1209600 // 2 weeks

	if v, ok := this.services[path]; !(ok && v > time.Now().Unix()) {
		_, e := this.consulClient.KV().Put(&api.KVPair{
			Key:   path,
			Value: []byte(fmt.Sprintf("%d", value)),
		}, nil)
		if e != nil {
			befw.LogWarning("[Syncer] can't write data to KV: ", path, ":", e.Error())
		}
		this.services[path] = value
		befw.LogInfo("[Syncer] wrote ", path, "to KV with value ", value)
	}
}

func (this *syncConfig) manageSession() {
	nodeName := fmt.Sprintf("%s.%s", this.consulDC, this.nodeName)
	// 1. register main node
	this.consulClient.Catalog().Register(&api.CatalogRegistration{
		Node:           nodeName,
		Address:        this.nodeAddr,
		Datacenter:     this.consulDC,
		SkipNodeUpdate: true,
	}, nil)
	if this.sessionID == "" {
		if sess, _, e := this.consulClient.Session().CreateNoChecks(
			&api.SessionEntry{
				Node: nodeName,
				Name: "befw-sync",
				TTL:  "30s",
			}, nil); e == nil {
			this.sessionID = sess
		}
	} else {
		if se, _, e := this.consulClient.Session().Info(this.sessionID, nil); e != nil || se == nil {
			befw.LogWarning("[Syncer] Can't find session:", this.sessionID)
			this.sessionID = ""
			this.manageSession() // a bit recursive
		} else {
			this.consulClient.Session().Renew(this.sessionID, nil)
		}
	}
}

func (this *syncConfig) manageSessionLock() bool {
	this.manageSession()
	if this.sessionID != "" {
		if v, _, e := this.consulClient.KV().Acquire(
			&api.KVPair{Key: "befw/.lock",
				Value:   []byte("ok"),
				Session: this.sessionID,
			}, nil); e != nil {
			befw.LogWarning("[Syncer] Can't create lock:", e.Error())
			return false
		} else {
			return v
		}
	}
	return false
}

func (this *syncConfig) cleanup() {
	nodeName := fmt.Sprintf("%s.%s", this.consulDC, this.nodeName)
	this.consulClient.Catalog().Deregister(&api.CatalogDeregistration{
		Node:       nodeName,
		Address:    this.nodeAddr,
		Datacenter: this.consulDC,
	}, nil)

}
