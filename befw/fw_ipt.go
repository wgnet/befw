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
    "errors"
    "sync"
    "strings"
    "os/exec"
    "github.com/wgnet/befw/logging"
    "fmt"
    "time"
    "strconv"
    "net"
    "encoding/json"
    "io/ioutil"
)

// Structure for iptables firewall manager
type FwIptables struct {
    savedIpset          map[string]string      // Used to check consistent
    savedRules          string
    appliedRules        string
    appliedIPSet        map[string]string
    lock                sync.Mutex

    rulesApply          func(rules string) error
    ipsetApply          func(name, rules string) error
    isIpsetConsistent   func() bool
    isRulesConsistent   func() bool
}

// Templates of iptables rules
type IptablesRules struct {
	Header   string `json:"header"`
	Footer   string `json:"footer"`
	Line     string `json:"rule_service"`
	LineE    string `json:"rule_service_e"`
	Static   string `json:"static_set"`
	NidsLine string `json:"nids_line"`
}

// Util structure: Keep data for templates
type iptablesPort struct {
	Port  string
	Proto string
}

// Default iptables rule templates
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

// Initialize new instance of 'iptables' firewall manager
func NewIptables() FwIptables {
    result := FwIptables{
        savedIpset:     make(map[string]string),
        appliedIPSet:   make(map[string]string),
    }
    result.rulesApply = result.binRulesApply
    result.ipsetApply = result.binIpsetApply
    result.isIpsetConsistent = result.binIsIpsetConsistent
    result.isRulesConsistent = result.binIsRulesConsistent
    return result
}

// Keep firewall consistent
//  Check if ipsets and rules didn't changed since last apply
func (fw FwIptables) KeepConsistent() error {
    fw.lock.Lock()
    defer fw.lock.Unlock()

    // Check ipset for consistency
    if !fw.isIpsetConsistent() {
        if e := fw.ipsetRestore(); e != nil { return e }
    }
    // Check iptables for consistency
    if !fw.isRulesConsistent() {
        if e := fw.rulesRestore(); e != nil { return e }
    }

    return nil
}

// Apply state
func (fw FwIptables) Apply(state *state) error {
    fw.lock.Lock()
    defer fw.lock.Unlock()

    ipsets := make(map[string][]string)

    // 1. Collect ipsets in one collection
    // 1.1. Append const IPSets
    for _, set  := range state.Config.StaticSetList {
        ipsets[set.Name] = make([]string, 0)
    }

    // 1.2. Append static IPSets
    for name, sets := range state.StaticIPSets {
        for _, set := range sets {
            ipsets[name] = append(ipsets[name], set)
        }
    }
    // 1.3. Append service ipsets
    for _, srv := range state.NodeServices {
        for _, set := range srv.Clients {
            if set.isExpired() { continue }
            ipsets[srv.Name] = append(ipsets[srv.Name], set.CIDR.String())
        }
    }
    // 2. Apply ipsets
    for name, set := range ipsets {
        e := fw.ipsetApply(name, fw.ipsetGenerate(name, set))
        if e != nil { return e }
    }
    // 3. Generate and apply services
    e := fw.rulesApply(fw.rulesGenerate(state))
    if e != nil { return e }
    return nil
}

// Restore last applied ipatables rules
func (fw FwIptables) rulesRestore() error {
    if fw.appliedRules == "" {
        logging.LogWarning("[IPT] Failed to restore: empty rules.")
        return nil
    }
    return fw.rulesApply(fw.appliedRules)
}

// Restore last applied ipsets
func (fw FwIptables) ipsetRestore() error {
    for name, rules := range fw.appliedIPSet {
        e := fw.ipsetApply(name, rules)
        if e != nil { return e }
    }
    return nil
}

// Generate text rules for 'iptables' with defined template
func (fw FwIptables) rulesGenerate(state *state) string {
    result := new(strings.Builder)
    templates := state.Config.newRules()
    replacer := strings.NewReplacer("{DATE}", time.Now().String())
    // 1. Header
    replacer.WriteString(result, templates.Header)
    // 2. NIDS
    if state.Config.NIDSEnable {
        result.WriteString(
            strings.Replace(templates.NidsLine,
                "{NIDSPORTS}", nidsPortsToString(nidsState.nPorts),
                -1))
    }
    // 3. Add rules for StaticSetList
    for _, set := range state.Config.StaticSetList {
        if _, ok := state.StaticIPSets[set.Name]; ok {
            if set.Target == "NOOP" { continue }
        }
        strings.NewReplacer("{NAME}", set.Name,
                            "{PRIORITY}", strconv.Itoa(set.Priority),
                            "{TARGET}", set.Target,
               ).WriteString(result, templates.Static)
    }
    // 4. Services
    for _, srv := range state.NodeServices {
        if state.StaticIPSets[srv.Name] == nil { continue }
        name := correctIPSetName(srv.Name)
        // Check template by service mode.
        var templateRule string = templates.Line
        if srv.Mode == MODE_ENFORCING { templateRule = templates.LineE }
        // Write rule lines
        ports := portsPerProtocolGenerate(srv, templates.Line)
        for _, line := range ports {
            strings.NewReplacer("{NAME}", name,
                                "{PORT}", line.Port,
                                "{PORTS}", line.Port,
                                "{PROTO}", line.Proto,
            ).WriteString(result, templateRule)
        }
    }
    // 5. Footer
    replacer.WriteString(result, templates.Footer)
    return result.String()
}

// Generate text rules for 'ipset' command
func (fw FwIptables) ipsetGenerate(name string, set []string) string {
    result := new(strings.Builder)
    name = correctIPSetName(name)
    tmp := fmt.Sprintf("tmp_%s", getRandomString())

    // 0. Doublecheck if ipset exists
    result.WriteString(fmt.Sprintln("create", name, "hash:net"))
    // 1. Create TMP and flusth
    result.WriteString(fmt.Sprintln("create", tmp, "hash:net"))
    result.WriteString(fmt.Sprintln("flush", tmp))
    // 2. Fill tmp ipset
    for _, cidr := range set {
        _, _, e := net.ParseCIDR(cidr)
        if e != nil { continue }
        if cidr == "0.0.0.0/0" {
            logging.LogWarning("[IPT] We will replace 0.0.0.0/0 as it's an ipset limitation")
            result.WriteString(fmt.Sprintln("add", tmp, "0.0.0.0/1"))
            result.WriteString(fmt.Sprintln("add", tmp, "128.0.0.0/1"))
            continue
        }
        result.WriteString(fmt.Sprintln("add", tmp, cidr))
    }
    // 3. Swap tmp and real ipset
    result.WriteString(fmt.Sprintln("swap", tmp, name))
    result.WriteString(fmt.Sprintln("destroy", tmp))
    return result.String()
}

// Initialize iptables templates
func (this *config) newRules() *IptablesRules {
	rules := defaultRules()
	if data, e := ioutil.ReadFile(this.RulesPath); e != nil {
		logging.LogWarning("[IPT] Can't read", this.RulesPath, "; using default:", e.Error())
	} else {
		if e := json.Unmarshal(data, rules); e != nil {
			logging.LogWarning("[IPT] Can't parse", this.RulesPath, "; using default:", e.Error())
		}
	}
	return rules
}

// Generate merged tcp/udp ports lines (many ports per one rule)
func  portsPerProtocolGenerate(srv bService, template string) []iptablesPort {
	var lines []iptablesPort
    var portRanges map[netProtocol][]string = map[netProtocol][]string{
        PROTOCOL_TCP: make([]string, 0),
        PROTOCOL_UDP: make([]string, 0),
    }
    for _, port := range srv.Ports {
        portRanges[port.Protocol] = append(portRanges[port.Protocol], port.Range())
    }
    for prot, portRange := range portRanges {
        if len(portRange) > 0 {
            lines = append(lines, iptablesPort{
                Port:  strings.Join(portRange, ", "),
                Proto: prot,
            })
        }
    }
    return lines
}

func (fw FwIptables) binIsIpsetConsistent() bool {
    for name := range fw.savedIpset {
        stdout := new(strings.Builder)
        stdout.Reset()
        cmd := exec.Command(getBinary("ipset"), "-o", "save", "list", name)
        cmd.Stdout = stdout
        if e := cmd.Run(); e != nil {
            logging.LogWarning("[IPT] Failed to check ipset consistancy:", name, e.Error())
            return false
        }
        if fw.savedIpset[name] != stdout.String() {
            return false
        }
    }
    return true
}

func (fw FwIptables) binIsRulesConsistent() bool {
    if fw.savedRules == "" { return true }
    stdout := new(strings.Builder)
    stdout.Reset()
    cmd := exec.Command(getBinary("iptables"), "-S", "BEFW")
    cmd.Stdout = stdout
    if e := cmd.Run(); e != nil {
        logging.LogWarning("[IPT] Failed to check iptables consistancy:", e.Error())
        return false
    }
    return fw.savedRules == stdout.String()
}

// Call 'ipset' binary to apply set-"rules"
func (fw FwIptables) binIpsetApply(name, rules string) error {
    // TODO: Check if IPv6 HERE.
    stdout := new(strings.Builder)
    cmd := exec.Command(getBinary("ipset"), "-exist", "restore")
    cmd.Stdin = strings.NewReader(rules)
    cmd.Stdout = stdout
    cmd.Stderr = stdout
    if e := cmd.Run(); e != nil {
        logging.LogWarning("[IPT] Failed to apply ipset:", stdout.String())
        logging.LogDebug("Rules (ipset):\n", rules)
        return errors.New(stdout.String())
    }
    // 3. Cleanup
    stdout.Reset()
    // 4. Save ipset state
    cmd = exec.Command(getBinary("ipset"), "-o", "save", "list", name)
    cmd.Stdout = stdout
    if e := cmd.Run(); e == nil {
        fw.savedIpset[name] = stdout.String()
    }
    fw.appliedIPSet[name] = rules
    return nil
}

// Call 'iptables' binary to apply rules
func (fw FwIptables) binRulesApply(rules string) error {
    // Execute
    stdout := new(strings.Builder)
    cmd := exec.Command(getBinary("iptables-restore"), "-n")
    cmd.Stdin = strings.NewReader(rules)
    cmd.Stdout = stdout
    cmd.Stderr = stdout
    if e := cmd.Run(); e != nil {
        logging.LogWarning("[IPT] Failed to apply iptables rules:", e.Error())
        logging.LogDebug("Rules (iptables):\n", rules, "\n----------\n", stdout.String())
        return errors.New(stdout.String())
    }
    // Save state
    stdout.Reset()
    cmd = exec.Command(getBinary("iptables"), "-S", "BEFW")
    cmd.Stdout = stdout
    if e := cmd.Run(); e == nil {
        fw.savedRules = stdout.String()
    }
    fw.appliedRules = rules
    return nil
}
