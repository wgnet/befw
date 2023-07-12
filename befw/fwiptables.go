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
    savedRules6         string
    appliedIPSet        map[string]string
    appliedRules        string
    appliedRules6       string
    lock                sync.Mutex

    // Mockable bin-call functions
    rulesApply          func(rules string) error
    ipsetApply          func(name, rules string) error
    isIpsetConsistent   func() bool
    isRulesConsistent   func() bool

    // Mockable ipv6 bin-call functions
    rules6Apply         func(rules string) error
    isRules6Consistent  func() bool
}

// Templates of iptables rules
type IptablesRules struct {
	Header   string `json:"header"`
	Footer   string `json:"footer"`
	Line     string `json:"rule_service"`
	LineE    string `json:"rule_service_e"`
	Static   string `json:"static_set"`
	NidsLine string `json:"nids_line"`
	Header6  string `json:"header6"`
	Footer6  string `json:"footer6"`
}

// Util structure: Keep data for templates
type iptablesPort struct {
	Port  string
	Proto string
}

// Default iptables rule templates
func defaultRules() *IptablesRules {
    lineRule := iptablesRulesLine
    if ENABLE_IPT_MULTIPORT { lineRule = iptablesRulesLineMulti }
	return &IptablesRules{
		Header:   iptablesRulesHeader,
		Footer:   iptablesRulesFooter,
		Line:     lineRule,
		LineE:    lineRule,
		Static:   iptablesStaticSet,
		NidsLine: iptablesNidsLine,
		Header6:  iptablesRulesHeader,
		Footer6:  iptablesRulesFooter,
	}
}

// Initialize new instance of 'iptables' firewall manager
func NewIptables() FwIptables {
    result := FwIptables{
        savedIpset:     make(map[string]string),
        appliedIPSet:   make(map[string]string),
    }
    // IPv4
    result.rulesApply = result.binRulesApply
    result.ipsetApply = result.binIpsetApply
    result.isIpsetConsistent = result.binIsIpsetConsistent
    result.isRulesConsistent = result.binIsRulesConsistent
    // IPv6
    result.rules6Apply        = result.binRules6Apply
    result.isRules6Consistent = result.binIsRules6Consistent

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
    // Check ip6tables for consistency
    if !fw.isRules6Consistent() {
        if e := fw.rules6Restore(); e != nil { return e }
    }

    return nil
}

// Apply state
func (fw FwIptables) Apply(state *state) error {
    fw.lock.Lock()
    defer fw.lock.Unlock()

    ipsets := make(map[string][]string)

    // 1. Collect ipsets in one collection
    // 1.1. Append const IPSets (empty too)
    for _, set  := range state.Config.StaticSetList {
        ipsets[set.Name] = make([]string, 0)
    }

    // 1.2. Append static IPSets
    for name, sets := range state.StaticIPSets {
        if _, ok := ipsets[name]; !ok { ipsets[name] = make([]string, 0)}   // empty? ok!
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
    // 2. Apply ipsets (v4 and v6)
    for name, set := range ipsets {
        e := fw.ipsetApply(name, fw.ipsetGenerate(name, set))
        if e != nil { return e }
    }
    // 3. Generate and apply services
    e := fw.rulesApply(fw.rulesGenerate(state, ipsets, false))
    if e != nil { return e }
    e = fw.rules6Apply(fw.rulesGenerate(state, ipsets, true))
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

// Restore last applied ip6atables rules
func (fw FwIptables) rules6Restore() error {
    if fw.appliedRules6 == "" {
        logging.LogWarning("[IP6T] Failed to restore: empty rules.")
        return nil
    }
    return fw.rules6Apply(fw.appliedRules6)
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
func (fw FwIptables) rulesGenerate(state *state, applied map[string][]string, ip6 bool) string {
    result := new(strings.Builder)
    templates := state.Config.newRules()
    replacer := strings.NewReplacer("{DATE}", time.Now().String())
    // 1. Header
    if ip6 {
        replacer.WriteString(result, templates.Header6)
    } else {
        replacer.WriteString(result, templates.Header)
    }
    // 2. NIDS
    if state.Config.NIDSEnable {
        result.WriteString(
            strings.Replace(templates.NidsLine,
                "{NIDSPORTS}", nidsPortsToString(nidsState.nPorts),
                -1))
    }
    // 3. Add rules for StaticSetList
    for _, set := range state.Config.StaticSetList {
        name := set.Name
        if _, ok := state.StaticIPSets[name]; ok {
            if set.Target == "NOOP" { continue }
        }
        if ip6 { name += V6 }
        name = correctIPSetName(name)
        strings.NewReplacer("{NAME}", name,
                            "{PRIORITY}", strconv.Itoa(set.Priority),
                            "{TARGET}", set.Target,
               ).WriteString(result, templates.Static)
    }
    // 4. Services
    for _, srv := range state.NodeServices {
        //if _, ok := state.StaticIPSets[srv.Name]; !ok && len(srv.Clients) <= 0 { continue }
        if _, ok := applied[srv.Name]; !ok { continue }
        name := srv.Name
        if ip6 { name += V6 }
        name = correctIPSetName(name)
        // Check template by service mode.
        var templateRule string = templates.Line
        if srv.Mode == MODE_ENFORCING { templateRule = templates.LineE }

        // Write rule lines
        if ENABLE_IPT_MULTIPORT {
            // Multiple ports per rule line:  --dports  1,2,3,...
            ports := portsPerProtocolGenerate(srv, templates.Line)
            for _, line := range ports {
                strings.NewReplacer("{NAME}", name,
                                    "{PORT}", line.Port,
                                    "{PORTS}", line.Port,
                                    "{PROTO}", line.Proto,
                ).WriteString(result, templateRule)
            }
        } else {
            // One port per rule line:  --dport 1
            for _, port := range srv.Ports {
                strings.NewReplacer(
                    "{NAME}",   name,
                    "{PORT}",   port.Range(),
                    "{PORTS}",  port.Range(),
                    "{PROTO}",  port.Protocol,
                ).WriteString(result, templateRule)
            }
        }
    }
    // 5. Footer
    if ip6 {
        replacer.WriteString(result, templates.Footer6)
    } else {
        replacer.WriteString(result, templates.Footer)
    }
    return result.String()
}

// Generate text rules for 'ipset' command
func (fw FwIptables) ipsetGenerate(name string, set []string) string {
    result := new(strings.Builder)
    name6 := correctIPSetName(name+V6)
    name = correctIPSetName(name)
    tmp := fmt.Sprintf("tmp_%s", getRandomString())
    tmp6 := fmt.Sprintf("tmp6_%s", getRandomString())

    // 0. Doublecheck if ipset exists
    result.WriteString(fmt.Sprintln("create", name, "hash:net"))
    result.WriteString(fmt.Sprintln("create", name6, "hash:net", "family inet6"))
    // 1. Create TMP and flusth
    result.WriteString(fmt.Sprintln("create", tmp, "hash:net"))
    result.WriteString(fmt.Sprintln("create", tmp6, "hash:net", "family inet6"))
    result.WriteString(fmt.Sprintln("flush", tmp))
    result.WriteString(fmt.Sprintln("flush", tmp6))
    // 2. Fill tmp ipset
    for _, cidr := range set {
        _, nt, e := net.ParseCIDR(cidr)
        if e != nil || nt == nil {
            logging.LogWarning("[IPT] Skip set. Can't parse CIDR: ", cidr)
            continue
        }
        if isIPv6(cidr)  {
            if nt.String() == "::/0" {
                logging.LogWarning("[IP6T] We will replace ::/0 as it's an ipset limitation")
                result.WriteString(fmt.Sprintln("add", tmp6, "::/1"))
                continue
            }
            result.WriteString(fmt.Sprintln("add", tmp6, cidr))
        } else {
            // Dirty replacement of ipset limitation for "0/0"-net
            if cidr == "0.0.0.0/0" {
                logging.LogWarning("[IPT] We will replace 0.0.0.0/0 as it's an ipset limitation")
                result.WriteString(fmt.Sprintln("add", tmp, "0.0.0.0/1"))
                result.WriteString(fmt.Sprintln("add", tmp, "128.0.0.0/1"))
                continue
            }
            result.WriteString(fmt.Sprintln("add", tmp, cidr))
        }
    }
    // 3. Swap tmp and real ipset
    result.WriteString(fmt.Sprintln("swap", tmp, name))
    result.WriteString(fmt.Sprintln("swap", tmp6, name6))
    result.WriteString(fmt.Sprintln("destroy", tmp))
    result.WriteString(fmt.Sprintln("destroy", tmp6))
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
        port := new(strings.Builder)
        for i, value := range portRange {
            if i > 0 { port.WriteString(",") }
            port.WriteString(value)
        }
        if len(port.String()) > 0 {
            lines = append(lines, iptablesPort{
                Port:  port.String(),
                Proto: prot,
            })
        }
    }
    return lines
}

func (fw FwIptables) binIsIpsetConsistent() bool {
    for name := range fw.savedIpset {
        out, err := run(nil, "ipset", "-o", "save", "list", name)
        if err != nil {
            logging.LogWarning("[IPT] Failed to check ipset consistency:", name, err.Error())
            return false
        }
        if fw.savedIpset[name] != out { return false }
    }
    return true
}

func (fw FwIptables) binIsRulesConsistent() bool {
    if fw.savedRules == "" { return true }
    out, err := run(nil, "iptables", "-S", "BEFW")
    if err != nil {
        logging.LogWarning("[IPT] Failed to check iptables consistency:", err.Error())
        return false
    }
    return fw.savedRules == out
}

// Check if ip6tables consistent
func (fw FwIptables) binIsRules6Consistent() bool {
    out, err := run(nil, "ipset", "-exist", "restore")
    if err != nil {
        logging.LogWarning("[IP6T] Failed to check ip6tables consistancy:", err.Error())
        return false
    }
    return fw.savedRules6 == out
}

// Call 'ipset' binary to apply set-"rules"
func (fw FwIptables) binIpsetApply(name, rules string) error {
    // Apply ipset
    out, err := run(&rules, "ipset", "-exist", "restore")
    if err != nil {
        logging.LogWarning("[IPT] Failed to apply ipset:", out)
        logging.LogDebug("Rules (ipset):\n", rules)
        return errors.New(out)
    }
    fw.appliedIPSet[name] = rules
    // Save ipset state
    out, err = run(nil, "ipset", "-o", "save", "list", name)
    if err == nil { fw.savedIpset[name] = out }
    return nil
}

// Call 'iptables' binary to apply rules
func (fw FwIptables) binRulesApply(rules string) error {
    // Apply rules
    out, err := run(&rules, "iptables-restore", "-n")
    if err != nil {
        logging.LogWarning("[IPT] Failed to apply iptables rules:", err.Error())
        logging.LogDebug("Rules (iptables-restore):\n", rules, "\n----------\n", out)
        return errors.New(out)
    }
    fw.appliedRules = rules
    // Save state
    out, err = run(nil, "iptables", "-S", "BEFW")
    if err == nil { fw.savedRules = out }
    return nil
}

func (fw FwIptables) binRules6Apply(rules string) error {
    // Execute
    stdout, err := run(&rules, "ip6tables-restore", "-n")
    if err != nil {
        logging.LogWarning("[IP6T] Failed to apply ip6tables rules:", err.Error())
        logging.LogDebug("Rules (ip6tables-restore):\n", rules, "\n----------\n", stdout)
        return errors.New(stdout)
    }
    fw.appliedRules6 = rules
    // Save state
    stdout, err = run(nil, "ip6tables", "-S", "BEFW")
    if err == nil { fw.savedRules6 = stdout }
    return nil
}
