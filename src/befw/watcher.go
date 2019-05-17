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
	"github.com/hashicorp/consul/api"
	"github.com/rjeczalik/notify"
	"math/rand"
	"sort"
	"time"
)

var notifyChannel = make(chan notify.EventInfo, 100)
var watchers = make(map[string]chan bool)

var WatchTimeout = 30 * time.Minute
var defaultDieTimeout = 10 * time.Second

var watcherStarted = false

func sleepIfNoChanges(state *state) {
	if !watcherStarted {
		state.config.startFileWatcher()
		watcherStarted = true
	}
	consulUpdateWatchers(state)
	select {
	case <-notifyChannel:
		break
	case <-time.After(WatchTimeout):
		break
	}
	cleanupChannel()
	// wait random 1-10 seconds to avoid simultaneously overload
	time.Sleep(time.Duration(1+rand.Intn(10)) * time.Second)
}

func cleanupChannel() {
	for {
		select {
		case <-notifyChannel:
			continue
		case <-time.After(time.Second):
			return
		}
	}
}

func (this *config) startFileWatcher() {

	if err := notify.Watch(this.ipsetDir, notifyChannel, notify.Remove, notify.Write);
		err != nil {
		LogWarning(err)
	} else {
		LogInfo("[Watcher] Start watching", this.ipsetDir)
	}
	if err := notify.Watch(this.rulesPath, notifyChannel, notify.All);
		err != nil {
		LogWarning(err)
	} else {
		LogInfo("[Watcher] Start watching", this.rulesPath)
	}
	if err := notify.Watch(this.servicesDir, notifyChannel, notify.Write, notify.Remove);
		err != nil {
		LogWarning(err)
	} else {
		LogInfo("[Watcher] Start watching", this.servicesDir)
	}
}

func consulUpdateWatchers(state *state) {
	// 1. create array of keys we need for this run
	keys := []string{"localServices", "befw/$alias$"}
	keys = append(keys, state.generateKVPaths("rules_allow")...)
	keys = append(keys, state.generateKVPaths("rules_deny")...)
	for _, s := range state.nodeServices {
		keys = append(keys, state.generateKVPaths(s.ServiceName)...)
	}
	sort.Strings(keys)
	in_keys := func(x string) bool {
		for _, y := range keys {
			if x == y {
				return true
			}
		}
		return false
	}
	// 2. stop old watchers not in keys
	for k, _ := range watchers {
		if !in_keys(k) {
			watchers[k] <- true
			delete(watchers, k)
			LogInfo("[Watcher] Watch key", k, "deleted from watch list")
		}
	}
	// 3. create new chan & watch services
	for _, k := range keys {
		if _, ok := watchers[k]; ok { // exists and running
			continue
		}
		watchers[k] = make(chan bool, 1)
		LogInfo("[Watcher] Watch key", k, "added to watch list")
		if k == "localServices" {
			go watchLocalServices(state, watchers[k])
		} else {
			go watchKVStore(k, state, watchers[k])
		}
	}

}

func watchLocalServices(state *state, chanExit chan bool) {
	services := make(map[string]int)
	if m, e := state.consulClient.Agent().Services(); e == nil {
		for name, s := range m {
			services[name] = s.Port
		}
		for {
			if m, e := state.consulClient.Agent().Services(); e == nil {
				for name, s := range m {
					if p, ok := services[name]; ok {
						if p == s.Port {
							continue
						}
					}
					LogInfo("[Watcher] Found new/changed service", name, "on port", s.Port)
					services[name] = s.Port
					notifyChannel <- nil
					break
				}
				for name, port := range services {
					if _, ok := m[name]; !ok {
						LogInfo("[Watcher] Found deleted service", name, "on port", port)
						delete(services, name)
						notifyChannel <- nil
						break
					}
				}
			}
			select {
			case <-chanExit:
				return
			case <-time.After(defaultDieTimeout):
				continue
			}
		}
	} else {
		LogWarning("[Watcher] LocalServices watcher is dead")
		return
	}
}

func watchKVStore(path string, state *state, chanExit chan bool) {
	var s_idx uint64 = 0
	if l, m, e := state.consulClient.KV().List(path, &api.QueryOptions{Datacenter: state.config.consulDC,}); e == nil {
		if len(l) != 0 {
			s_idx = m.LastIndex
		}
	}

	for {
		select {
		case <-chanExit:
			return
		case <-time.After(defaultDieTimeout):
			break
		}
		q := &api.QueryOptions{Datacenter: state.config.consulDC,
			WaitTime: defaultDieTimeout, WaitIndex: s_idx}
		if l, m, e := state.consulClient.KV().List(path, q); e == nil {
			if len(l) == 0 {
				if s_idx != 0 {
					LogInfo("[Watcher] KVStore (", path, ") has been purged")
					s_idx = 0
					notifyChannel <- nil // was > 0 and got 0
				}
			} else {
				if m.LastIndex > s_idx {
					LogInfo("[Watcher] KVStore (", path, ") has been changed")
					s_idx = m.LastIndex
					notifyChannel <- nil
				}
			}
		}
	}
}
