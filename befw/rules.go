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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wgnet/befw/logging"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IptablesPort struct {
	Port  string
	Proto string
}

type IptablesRules struct {
	Header   string `json:"header"`
	Footer   string `json:"footer"`
	Line     string `json:"rule_service"`
	LineE    string `json:"rule_service_e"`
	Static   string `json:"static_set"`
	NidsLine string `json:"nids_line"`
}

func defaultRules() *IptablesRules {
	return &IptablesRules{
		Header:   iptablesRulesHeader,
		Footer:   iptablesRulesFooter,
		Line:     iptablesRulesLine,
		LineE:    iptablesRulesLine,
		Static:   iptablesStaticSet,
		NidsLine: iptablesNidsLine,
	}
}
func (this *config) newRules() *IptablesRules {
	rules := defaultRules()
	if data, e := ioutil.ReadFile(this.RulesPath); e != nil {
		logging.LogWarning("[Rules] Can't read", this.RulesPath, "; using default:", e.Error())
	} else {
		if e := json.Unmarshal(data, rules); e != nil {
			logging.LogWarning("[Rules] Can't parse", this.RulesPath, "; using default:", e.Error())
		}
	}

	return rules
}

var lastIPSetContent = make(map[string]string)
var lastIPTablesContent string
var lastAppliedRules string
var lastContentLock sync.Mutex

func (state *state) generateRules() string {
	rules := state.Config.newRules()
	result := new(strings.Builder)
	replacer1 := strings.NewReplacer("{DATE}", time.Now().String())
	replacer1.WriteString(result, rules.Header)
	if state.Config.NIDSEnable {
		result.WriteString(strings.Replace(rules.NidsLine,
			"{NIDSPORTS}",
			nidsPortsToString(nidsState.nPorts),
			-1))
	}
	for _, set := range state.Config.StaticSetList {
		if _, ok := state.IPSets[set.Name]; ok {
			if set.Target == "NOOP" {
				continue
			}
			strings.NewReplacer(
				"{NAME}", set.Name, "{PRIORITY}", strconv.Itoa(set.Priority), "{TARGET}", set.Target).WriteString(result, rules.Static)
		}
	}
	for _, srv := range state.NodeServices {
		if state.IPSets[srv.Name] == nil {
			continue
		}

		name := cutIPSet(srv.Name)
		ports := templateFwPorts(srv, rules.Line)

		// Write rule lines
        var enforcing bool = false
        var templateRule string = rules.Line
        if enforcing { templateRule = rules.LineE }
		for _, line := range ports {
            strings.NewReplacer(
                "{NAME}", name,
                "{PORT}", line.Port,
                "{PORTS}", line.Port,
                "{PROTO}", line.Proto,
            ).WriteString(result, templateRule)
        }
	}
	replacer1.WriteString(result, rules.Footer)
	return result.String()
}

func templateFwPorts(srv bService, template string) []IptablesPort {
	var lines []IptablesPort
    var portRanges map[netProtocol][]string = map[netProtocol][]string{
        PROTOCOL_TCP: make([]string, 5),
        PROTOCOL_UDP: make([]string, 5),
    }
    for _, port := range srv.Ports {
        portRanges[port.Protocol] = append(portRanges[port.Protocol], port.Range())
    }
    for prot, portRange := range portRanges {
        if len(portRange) > 0 {
            lines = append(lines, IptablesPort{
                Port:  strings.Join(portRange, ", "),
                Proto: prot,
            })
        }
    }
    return lines
}


func applyRules(rules string) error {
	stdout := new(strings.Builder)
	cmd := exec.Command(getBinary("iptables-restore"), "-n")
	cmd.Stdin = strings.NewReader(rules)
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	if e := cmd.Run(); e != nil {
		logging.LogWarning("[Rules] Can't refresh rules:", e.Error())
		logging.LogDebug(rules, "\n---------\n", stdout.String())
		return errors.New(stdout.String())
	}
	// save it now
	stdout.Reset()
	cmd = exec.Command(getBinary("iptables"), "-S", "BEFW")
	cmd.Stdout = stdout
	if e := cmd.Run(); e == nil {
		lastIPTablesContent = stdout.String()
	}
	lastAppliedRules = rules
	return nil
}

var randDict []byte

func applyIPSet(ipsetName string, cidrList []string) (bool, error) {
	ipset := new(strings.Builder)
	if ipsetName == "" {
		return false, errors.New("ipset Name eq ''")
	}
	ipsetName = cutIPSet(ipsetName)
	tmpIpsetName := fmt.Sprintf("tmp-%s", getRandomString())
	ipset.WriteString(fmt.Sprintln("create", ipsetName, "hash:net"))
	ipset.WriteString(fmt.Sprintln("create", tmpIpsetName, "hash:net"))
	ipset.WriteString(fmt.Sprintln("flush", tmpIpsetName))
	for _, cidr := range cidrList {
		// TODO: more accurate fix
		if cidr == "0.0.0.0/0" {
			logging.LogWarning("[Rules] we will replace 0.0.0.0/0 as it's an ipset limitation")
			ipset.WriteString(fmt.Sprintln("add", tmpIpsetName, "0.0.0.0/1"))
			ipset.WriteString(fmt.Sprintln("add", tmpIpsetName, "128.0.0.0/1"))
			continue
		}
		ipset.WriteString(fmt.Sprintln("add", tmpIpsetName, cidr))
	}
	ipset.WriteString(fmt.Sprintln("swap", tmpIpsetName, ipsetName))
	ipset.WriteString(fmt.Sprintln("destroy", tmpIpsetName))
	stdout := new(strings.Builder)
	cmd := exec.Command(getBinary("ipset"), "-exist", "restore")
	cmd.Stdin = strings.NewReader(ipset.String())
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	if e := cmd.Run(); e != nil {
		logging.LogWarning("[Rules] IPSet refresh error:", stdout.String())
		logging.LogDebug(ipset.String())
		return false, errors.New(stdout.String())
	}
	// do fill check
	stdout.Reset()
	cmd = exec.Command(getBinary("ipset"), "-o", "save", "list", ipsetName)
	cmd.Stdout = stdout
	if e := cmd.Run(); e == nil {
		lastIPSetContent[ipsetName] = stdout.String()
	}
	return true, nil

}

func checkRulesIsConsistent() bool {
	if lastIPTablesContent != "" {
		stdout := new(strings.Builder)
		stdout.Reset()
		cmd := exec.Command(getBinary("iptables"), "-S", "BEFW")
		cmd.Stdout = stdout
		if e := cmd.Run(); e == nil {
			return lastIPTablesContent == stdout.String()
		} else {
			return false
		}
	}
	return true
}

func checkIpsetIsConsistent() bool {
	for ipsetName := range lastIPSetContent {
		stdout := new(strings.Builder)
		stdout.Reset()
		cmd := exec.Command(getBinary("ipset"), "-o", "save", "list", ipsetName)
		cmd.Stdout = stdout
		if e := cmd.Run(); e == nil {
			if lastIPSetContent[ipsetName] != stdout.String() {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func restoreLastRules() {
	if lastAppliedRules != "" {
		applyRules(lastAppliedRules)
	}
}

func restoreLastIPSet() {
	for ipsetName := range lastIPSetContent {
		state := strings.Split(lastIPSetContent[ipsetName], "\n")
		stdin := strings.NewReader(strings.Join(append(state[:1], append([]string{fmt.Sprintf("flush %s", ipsetName)}, state[2:]...)...), "\n"))
		cmd := exec.Command(getBinary("ipset"), "restore", "-exist")
		cmd.Stdin = stdin
		if e := cmd.Run(); e != nil {
		}

	}
}

func checkIsConsistent() {
	lastContentLock.Lock()
	defer lastContentLock.Unlock()
	if !checkIpsetIsConsistent() {
		logging.LogWarning("[Consist] ipset content was changed, going to restore")
		restoreLastIPSet()
		return
	}
	if !checkRulesIsConsistent() {
		logging.LogWarning("[Consist] iptables content was changed, going to restore")
		restoreLastRules()
		return
	}
}

func (conf *config) createStaticIPSets() {
	var b bytes.Buffer
	for _, staticSet := range conf.StaticSetList {
		b.WriteString(fmt.Sprintf("create %s hash:net\n", staticSet.Name))
	}
	cmd := exec.Command(getBinary("ipset"), "restore", "-exist")
	cmd.Stdin = &b
	if e := cmd.Run(); e != nil {
		logging.LogWarning("[Consist] can't create static ipsets")
		return
	}
}
