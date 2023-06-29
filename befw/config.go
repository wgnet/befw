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
	"bufio"
	"github.com/wgnet/befw/logging"
	"os"
	"strconv"
	"strings"
	"time"
)

var OverrideConfig = make(map[string]string)

type config struct {
	ConsulAddr     string
	ConsulDC       string
	NodeName       string
	NodeDC         string
	ConsulToken    string
	ServicesDir    string
	IPSetDir       string
	RulesPath      string
	WhitelistIPSet []string
	StaticSetList  []staticIPSetConf
	Timeout        befwConfigTimoutType
	NIDSEnable     bool
}

type RefreshMethod int8

type befwConfigTimoutType struct {
	Consul      time.Duration
	ConsulWatch time.Duration
}

func createConfig(configFile string) *config {
	ret := &config{
		ConsulAddr:     consulAddress,
		ConsulDC:       aclDatacenter,
		ConsulToken:    "",
		IPSetDir:       staticIpsetPath,
		ServicesDir:    staticServicesPath,
		RulesPath:      staticRulesPath,
		WhitelistIPSet: make([]string, 0),
		StaticSetList:  staticIPSetList, // default, TODO: make a Config
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
		logging.LogWarning("[Config] can't open", configFile, ":", e.Error())
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
		setConfigKV(&ret.ConsulAddr, "address", OverrideConfig, kv)
		setConfigKV(&ret.ConsulDC, "dc", OverrideConfig, kv)
		setConfigKV(&ret.ConsulToken, "token", OverrideConfig, kv)
		setConfigKV(&ret.IPSetDir, "ipsets", OverrideConfig, kv)
		setConfigKV(&ret.ServicesDir, "services", OverrideConfig, kv)
		setConfigKV(&ret.RulesPath, "rules", OverrideConfig, kv)
		setConfigKV(&ret.NodeName, "nodename", OverrideConfig, kv)
		setConfigKV(&ret.NodeDC, "nodedc", OverrideConfig, kv)
		setConfigKVSeconds(&ret.Timeout.Consul, "consul_timeout_sec", OverrideConfig, kv)
		setConfigKVSeconds(&ret.Timeout.ConsulWatch, "consulwatch_timeout_sec", OverrideConfig, kv)
		setConfigKVBool(&ret.NIDSEnable, "nids", OverrideConfig, kv)

		if _, ok := kv["fail"]; ok {
			logging.LogError("[Config] you must edit your Config file before proceed")
		}
		n := 3
		for k, v := range kv {
			if confSetPrefix+allowIPSetName == k {
				v0 := strings.Split(v, ";")
				ret.WhitelistIPSet = v0
				continue
			}
			if strings.HasPrefix(k, confSetPrefix) {
				set := staticIPSetConf{Name: strings.TrimPrefix(k, confSetPrefix)}
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
				logging.LogDebug("New local set: ", set.Name)
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
func setConfigKVBool(dest *bool, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			if b, e := strconv.ParseBool(value); e == nil {
				*dest = b
			}
			return
		}
	}
}

func setConfigKVSeconds(dest *time.Duration, key string, kvs ...map[string]string) {
	for _, kv := range kvs {
		if value, ok := kv[key]; ok {
			if i, err := strconv.Atoi(value); err == nil {
				*dest = time.Duration(i) * time.Second
				return
			}
		}
	}
}
