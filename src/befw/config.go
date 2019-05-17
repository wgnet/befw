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
	"os"
	"strings"
)

func createConfig(configFile string) *config {
	ret := &config{
		consulAddr:  consulAddress,
		consulDC:    aclDatacenter,
		consulToken: "",
		ipsetDir:    staticIpsetPath,
		servicesDir: staticServicesPath,
		rulesPath:   staticRulesPath,
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
		if v, ok := kv["address"]; ok {
			ret.consulAddr = v
		}
		if v, ok := kv["dc"]; ok {
			ret.consulDC = v
		}
		if v, ok := kv["token"]; ok {
			ret.consulToken = v
		}
		if v, ok := kv["ipsets"]; ok {
			ret.ipsetDir = v
		}
		if v, ok := kv["services"]; ok {
			ret.servicesDir = v
		}
		if v, ok := kv["rules"]; ok {
			ret.rulesPath = v
		}
		if _, ok := kv["fail"]; ok {
			LogError("[Config] you must edit your config file before proceed")
		}
	}
	return ret
}
