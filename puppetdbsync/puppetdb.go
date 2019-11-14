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
	"github.com/wgnet/befw/befw"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func (conf *syncConfig) requestPuppetDB() []*syncData {
	var response *http.Response
	var e error
	ret := make([]*syncData, 0)
	req, e := http.NewRequest("GET", conf.url, nil)
	if e != nil {
		befw.LogWarning("[Syncer] Cant request puppetdbsync: ", e.Error())
		return ret
	}
	req.Header.Set("Connection", "close")
	if response, e = conf.httpClient.Do(req); e != nil {
		befw.LogWarning("[Syncer] Cant request puppetdbsync: ", e.Error())
		return ret
	}
	if response.StatusCode != 200 {
		befw.LogWarning("[Syncer] Cant request puppetdbsync: ", response.Status)
		return ret
	}
	// debug
	var result []map[string]interface{}
	if data, e := ioutil.ReadAll(response.Body); e != nil {
		befw.LogWarning("[Syncer] Cant read puppetdbsync response: ", e.Error())
		return ret
	} else {
		if e := json.Unmarshal(data, &result); e != nil {
			befw.LogWarning("[Syncer] Cant parse puppetdbsync response: ", e.Error())
			return ret
		}
	}
	toSort := make([]string, 0)
	for _, value := range result {
		if _, ok := value["parameters"]; ok {
			if paramsMap, ok := value["parameters"].(map[string]interface{}); ok {
				if message, ok := paramsMap["message"]; ok {
					if stringMessage, ok := message.(string); ok {
						toSort = append(toSort, stringMessage)
					}
				}
			}
		}
	}
	sort.Strings(toSort)
	isEqual := true
	if conf.lastCounter < 360 {
		if conf.lastResult != nil {
			if len(toSort) == len(conf.lastResult) {
				for i, _ := range toSort {
					if toSort[i] != conf.lastResult[i] {
						isEqual = false
						break
					}
				}
			} else {
				isEqual = false
			}
		} else {
			isEqual = false
		}
	} else {
		isEqual = false
	}
	conf.lastResult = make([]string, len(toSort))
	copy(conf.lastResult, toSort)
	if !isEqual {
		conf.lastCounter = 0
		for _, stringMessage := range toSort {
			if newElem := conf.newSyncData(stringMessage); newElem != nil {
				ret = append(ret, newElem)
			}
		}
	} else {
		conf.lastCounter++
		//befw.LogDebug("[Syncer] Nothing changed, skipping update")
	}
	return ret
}

func (conf *syncConfig) validate(data *syncData) bool {
	conf.cacheMutex.RLock()
	defer conf.cacheMutex.RUnlock()
	var sOk, dOk, nOk, vOk bool
	if strings.HasPrefix(data.value, "$") && strings.HasSuffix(data.value, "$") {
		vOk = true
	} else if _, _, e := net.ParseCIDR(data.value); e == nil {
		vOk = true
	} else if e := net.ParseIP(data.value); e != nil {
		vOk = true
	}
	if data.service != "" {
		svcs := strings.Split(data.service, "_")
		l := len(svcs)
		if l >= 3 {
			if svcs[l-2] == "tcp" || svcs[l-2] == "udp" {
				if i, e := strconv.Atoi(svcs[l-1]); e == nil && i > 0 && i < 65535 {
					sOk = true
				}
			}
		}
	}
	if data.dc == "" {
		dOk = true
	} else {
		if _, ok := conf.cache.dcs[data.dc]; ok {
			dOk = true
		}
		if conf.cache.error {
			dOk = true
		}
	}
	if data.node == "" {
		nOk = true
	} else {
		if _, ok := conf.cache.nodes[data.dc+"@"+data.node]; ok {
			nOk = true
		}
		if conf.cache.error {
			nOk = true
		}
	}
	return sOk && dOk && nOk && vOk
}

func (conf *syncConfig) newSyncData(message string) *syncData {
	ret := new(syncData)
	if strings.IndexByte(message, '@') < 0 {
		return nil
	}
	elems := strings.Split(message, "@")
	for i := 0; i < len(elems); i++ {
		elems[i] = strings.ToLower(elems[i]) // tolower
	}
	switch len(elems) {
	case 2:
		ret.service = elems[0]
		ret.value = elems[1]
		break
	case 3:
		ret.service = elems[0]
		ret.dc = elems[1]
		ret.value = elems[2]
		break
	case 4:
		ret.service = elems[0]
		ret.dc = elems[1]
		ret.node = elems[2]
		ret.value = elems[3]
		break
	default:
		return nil
	}
	if ret.node != "" {
		ret.node = strings.Split(ret.node, ".")[0] // remove ..xxx
	}
	if conf.validate(ret) {
		return ret
	}
	return nil
}
