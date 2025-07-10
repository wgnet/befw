/**
 * Copyright 2018-2025 Wargaming Group Limited
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
	"fmt"
	"github.com/wgnet/befw/logging"
	"strings"
)

// Global resolver:
var aliasResolver = AliasResolver{
	cache:   make(map[string][]string),
	updater: nil,
}

type AliasResolver struct {
	cache   map[string][]string
	updater func(string) []string
}

// Resolve
func (a *AliasResolver) Resolve(key string) []string {
	// Cached
	if data, ok := a.cache[key]; ok {
		return data
	}

	a.cache[key] = make([]string, 0)
	uniq := make(map[string]bool)

	addrs := a.Update(key)
	aliases := make([]string, 0)
	// Resolve addresses first
	for _, addr := range addrs {
		if isAlias(addr) {
			aliases = append(aliases, addr)
		} else {
			uniq[addr] = true
		}
	}
	// Resolve aliases next
	for _, alias := range aliases {
		for _, addr := range a.Resolve(alias) {
			uniq[addr] = true
		}
	}

	// Put addresses into map
	for addr, _ := range uniq {
		a.cache[key] = append(a.cache[key], addr)
	}

	return a.cache[key]
}

// Update cache by name
func (a *AliasResolver) Update(key string) []string {
	if a.updater != nil {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered: ", r)
			}
		}()
		return a.updater(key)
	}
	return []string{}
}

// Clear cache
func (a *AliasResolver) Clear() {
	a.cache = make(map[string][]string)
}

func isAlias(addr string) bool {
	if strings.HasPrefix(addr, "$") &&
		strings.HasSuffix(addr, "$") {
		return true
	}
	return false
}

func (s *state) consulAlias(key string) []string {
	path := fmt.Sprintf("befw/$alias$/%s/", key)
	result := []string{}
	logging.LogDebug(fmt.Sprintf("Request Consul alias %s", path))
	if kvs, e := s.consulKVList(path); e != nil {
		logging.LogWarning("Failed to obtain Consul KV alias data [", path, "]: ", e.Error())
	} else {
		for _, kvp := range kvs {
			if kvp.Value == nil {
				continue
			}
			if netstr := path2netpart(kvp.Key); netstr != "" {
				result = append(result, netstr)
			}
		}
	}
	return result
}
