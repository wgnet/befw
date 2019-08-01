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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type IptablesRules struct {
	Header string `json:"header"`
	Footer string `json:"footer"`
	Line   string `json:"rule_service"`
	Static string `json:"static_set"`
}

func defaultRules() *IptablesRules {
	return &IptablesRules{
		Header: iptablesRulesHeader,
		Footer: iptablesRulesFooter,
		Line:   iptablesRulesLine,
		Static: iptablesStaticSet,
	}
}
func (this *config) newRules() *IptablesRules {
	rules := defaultRules()
	if data, e := ioutil.ReadFile(this.rulesPath); e != nil {
		LogWarning("[Rules] Can't read", this.rulesPath, "; using default:", e.Error())
	} else {
		if e := json.Unmarshal(data, rules); e != nil {
			LogWarning("[Rules] Can't parse", this.rulesPath, "; using default:", e.Error())
		}
	}
	return rules
}

func (this *state) generateRules() string {
	rules := this.config.newRules()
	result := new(strings.Builder)
	replacer1 := strings.NewReplacer("{DATE}", time.Now().String())
	replacer1.WriteString(result, rules.Header)
	for _, set := range this.config.setList {
		if _, ok := this.ipsets[set.name]; ok {
			if set.target == "NOOP" {
				continue
			}
			strings.NewReplacer(
				"{NAME}", set.name, "{PRIORITY}", strconv.Itoa(set.priority), "{TARGET}", set.target).WriteString(result, rules.Static)
		}
	}
	for _, serv := range this.nodeServices {
		if this.ipsets[serv.ServiceName] != nil {
			strings.NewReplacer(
				"{NAME}", cutIPSet(serv.ServiceName),
				"{PORT}", strconv.Itoa(int(serv.ServicePort)),
				"{PROTO}", string(serv.ServiceProtocol)).WriteString(result, rules.Line)
			if serv.ServicePorts != nil {
				for _, port := range serv.ServicePorts {
					strings.NewReplacer(
						"{NAME}", cutIPSet(serv.ServiceName),
						"{PORT}", strconv.Itoa(int(port.Port)),
						"{PROTO}", string(port.PortProto)).WriteString(result, rules.Line)
				}
			}
		}
	}
	replacer1.WriteString(result, rules.Footer)
	return result.String()
}

func applyRules(rules string) error {
	stdout := new(strings.Builder)
	cmd := exec.Command("/usr/sbin/iptables-restore", "-n")
	cmd.Stdin = strings.NewReader(rules)
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	if e := cmd.Run(); e != nil {
		LogWarning("[Rules] Can't refresh rules:", e.Error())
		if ConfigurationRunning == DebugConfiguration {
			println(rules)
			println("------")
			println(stdout.String())
		}
		return errors.New(stdout.String())
	}
	return nil
}

var randDict []byte

func getRandomString() string {
	// random of 30
	if randDict == nil {
		randDict = make([]byte, 26*2+10)
		for i := 'A'; i <= 'Z'; i++ {
			randDict[i-'A'] = byte(i)
		}
		for i := 'a'; i <= 'z'; i++ {
			randDict[26+i-'a'] = byte(i)
		}
		for i := '0'; i <= '9'; i++ {
			randDict[52+i-'0'] = byte(i)
		}
	}
	v := make([]byte, 25)
	for i := 0; i < 25; i++ {
		v[i] = randDict[rand.Intn(len(randDict)-1)]
	}
	return string(v)
}

func cutIPSet(ipsetName string) string {
	if len(ipsetName) > 31 { // max size of links
		parts := strings.Split(ipsetName, "_")
		leftLength := 31 - len(parts[len(parts)-1]) // we can't reduce last part
		maxPartLen := int((leftLength/(len(parts)-1) - 1))
		for i := 0; i < len(parts)-1; i++ {
			if len(parts[i]) > maxPartLen {
				parts[i] = string([]byte(parts[i])[0:maxPartLen]) // trim to size
			}
		}
		return strings.Join(parts, "_")
	} else {
		return ipsetName
	}
}
func applyIPSet(ipsetName string, cidrList []string) (bool, error) {
	ipset := new(strings.Builder)
	if ipsetName == "" {
		return false, errors.New("ipset name eq ''")
	}
	ipsetName = cutIPSet(ipsetName)
	tmpIpsetName := fmt.Sprintf("tmp-%s", getRandomString())
	ipset.WriteString(fmt.Sprintln("create", ipsetName, "hash:net"))
	ipset.WriteString(fmt.Sprintln("create", tmpIpsetName, "hash:net"))
	ipset.WriteString(fmt.Sprintln("flush", tmpIpsetName))
	for _, cidr := range cidrList {
		// TODO: more accurate fix
		if cidr == "0.0.0.0/0" {
			LogWarning("[Rules] we will replace 0.0.0.0/0 as it's an ipset limitation")
			ipset.WriteString(fmt.Sprintln("add", tmpIpsetName, "0.0.0.0/1"))
			ipset.WriteString(fmt.Sprintln("add", tmpIpsetName, "128.0.0.0/1"))
			continue
		}
		ipset.WriteString(fmt.Sprintln("add", tmpIpsetName, cidr))
	}
	ipset.WriteString(fmt.Sprintln("swap", tmpIpsetName, ipsetName))
	ipset.WriteString(fmt.Sprintln("destroy", tmpIpsetName))
	stdout := new(strings.Builder)
	cmd := exec.Command("/usr/sbin/ipset", "-exist", "restore")
	cmd.Stdin = strings.NewReader(ipset.String())
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	if e := cmd.Run(); e != nil {
		LogWarning("[Rules] IPSet refresh error:", stdout.String())
		if ConfigurationRunning == DebugConfiguration {
			println("-------")
			println(ipset.String())
			println("-------")
		}
		return false, errors.New(stdout.String())
	}
	return true, nil

}
