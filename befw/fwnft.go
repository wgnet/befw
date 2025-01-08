/**
 * Copyright 2018-2024 Wargaming Group Limited
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
	"os"
	"strings"

	"github.com/wgnet/befw/logging"
)

// NFT - BEFW with nftables.
type NFT struct {
	RulesApplied     string
	RulesAppliedHash string
	RealHash         string

	bin binNFT
}

type binNFT interface {
	ApplyRules(rules string) error
	ListRuleset(table string) (string, error)
}

type prodBinNFT struct{}
type nft_ipsets = map[string][]string // Shortcut for type

// Table names:
const (
	nft_befw        = "befw"
	nft_rule_file   = befwState + "/rules.nft"
	nft_prefix      = "[NFT] "
	nft_setname_max = 15
	nft_ip4         = "ip4_" // len <= 4
	nft_ip6         = "ip6_" // len <= 4
)

// Templates:
const (
	nft_table_reset   = "add table inet <TABLE>;\ndelete table inet <TABLE>;\nadd table inet <TABLE>;\n"
	nft_add_set       = "add set inet <TABLE> <SET> {type <TYPE>; flags interval;auto-merge;};\n"
	nft_add_set_6     = "add set inet <TABLE> <SET6> {type <TYPE6>; flags interval;auto-merge;};\n"
	nft_chain         = "add chain inet <TABLE> filter {type filter hook input priority <PRIORITY>; policy <POLICY>;};\n"
	nft_add_el        = "add element inet <TABLE> <SET> { <EL> };\n"
	nft_add_el_6      = "add element inet <TABLE> <SET6> { <EL6> };\n"
	nft_nids          = "add rule inet <TABLE> filter <PORTS> log group 402\n;"
	nft_static_rule   = "add rule inet <TABLE> filter ip saddr <SADDR> <TARGET>;\n"
	nft_static_rule_6 = "add rule inet <TABLE> filter ip6 saddr <SADDR6> <TARGET>;\n"
	nft_rule          = "add rule inet <TABLE> filter ip saddr <SADDR> <PORTS> accept;\nadd rule inet <TABLE> filter ip saddr <SADDR> <PORTS> log group 402\n;"
	nft_rule_6        = "add rule inet <TABLE> filter ip6 saddr <SADDR6> <PORTS> accept;\nadd rule inet <TABLE> filter ip6 saddr <SADDR6> <PORTS> log group 402\n;"
	nft_footer        = "# <NAME> - <SET> | <SET6>;\n"
)

// New instance of NFT:
func NewNFT() *NFT {
	logging.LogDebug(nft_prefix, "Initialize NFT firewall provider")
	// Create directory for rule-file
	os.MkdirAll(befwState, 0755)

	nft := NFT{
		bin: &prodBinNFT{},
	}

	return &nft
}

// Implement Firewall interface:
func (n *NFT) Apply(state *state) error {
	logging.LogDebug(nft_prefix, "Run Apply state")

	// Generate rules:
	rulesBEFW := n.generateRuleFile(nft_befw, "0", state)

	// Check if changed since last time
	hash := hashMD5(rulesBEFW)
	if n.RulesAppliedHash == hash {
		logging.LogDebug(nft_prefix, "SKIP APPLY. Rule was already applied")
		return nil
	}

	// Apply (swap with tmp table)
	err := n.bin.ApplyRules(rulesBEFW)
	if err != nil {
		return err
	}

	// Store hash
	ruleset, err := n.bin.ListRuleset(nft_befw)
	if err != nil {
		return err
	}
	n.RulesApplied = rulesBEFW
	n.RulesAppliedHash = hash
	n.RealHash = hashMD5(ruleset)

	logging.LogInfo(nft_prefix, "State was applied.") // TODO: Log whats new
	return nil
}

// Firewall:
func (n *NFT) KeepConsistent() error {
	logging.LogDebug(nft_prefix, "Run KeepConsistent.")
	// TODO Add counter of failrues - go to panic mode if many times in a row failed
	if len(n.RulesApplied) == 0 {
		logging.LogDebug(nft_prefix, "SKIP Consistency check: there is no applied rules yet.")
		return nil
	}
	ruleset, err := n.bin.ListRuleset(nft_befw)
	if err != nil {
		logging.LogDebug(nft_prefix, "Failed to list table: ", err)
		//return err
	}
	if err != nil || hashMD5(ruleset) != n.RealHash {
		logging.LogDebug(nft_prefix, "Consistency changed... Start restore")
		// Restore (tmp->rules)
		for _, rules := range []string{n.RulesApplied} {
			err := n.bin.ApplyRules(rules)
			if err != nil {
				return err
			}
		}
		logging.LogWarning(nft_prefix, "Consistency recovered: state was reapplied.")
	}
	return nil
}

// Collect const, static and service clients  addresses to sets:
func (n *NFT) collectIPSets(state *state) nft_ipsets {
	ipsets := make(nft_ipsets) // Init result map

	//   1. Const IPsets (rules_deny, rules_allow) (will be filled with static, but should exists!)
	for _, set := range state.Config.StaticSetList {
		ipsets[set.Name] = make([]string, 0)
	}

	//   2. Static IPSets
	for name, set := range state.StaticIPSets {
		// TODO:  Is it really should be appended, or can be just copied?
		// Add empty set
		if _, ok := ipsets[name]; !ok {
			ipsets[name] = make([]string, len(set))
		}
		// Append sets:
		ipsets[name] = append(ipsets[name], set...)
	}

	//   3. Service IPSets:
	for _, srv := range state.NodeServices {
		for _, addr := range srv.Clients {
			if !addr.isExpired() {
				ipsets[srv.Name] = append(ipsets[srv.Name], addr.CIDR.String())
			}
		}
	}
	return ipsets
}

func (n *NFT) generateRuleFile(table string, priority string, state *state) string {
	// Colect ipsets
	ipsets := n.collectIPSets(state)
	// Generate short names for IP sets (avoid collisions):  map[short]full
	shortNames := make(map[string]string)
	for name, _ := range ipsets {
		nftSetName(name, shortNames)
	}
	// Reverse map of short names map[full]short
	setNames := make(map[string]string)
	for short, full := range shortNames {
		setNames[full] = short
	}

	// Generate rules
	result := new(strings.Builder)

	n.writeRuleInit(table, result)
	n.writeRuleIPSets(table, result, ipsets, setNames)
	n.writeRuleChains(table, priority, result)
	n.writeRuleHeader(table, result)
	n.writeRuleNIDS(table, result, state)
	n.writeRuleStaticSet(table, result, state, setNames)
	n.writeRuleServices(table, result, state, setNames)
	n.writeRuleFooter(table, result, setNames)

	return result.String()
}

func (n *NFT) writeRuleInit(table string, rules *strings.Builder) {
	// Init (flush table)
	replacer := strings.NewReplacer(
		"<TABLE>", table,
	)
	replacer.WriteString(rules, nft_table_reset)
}

func (n *NFT) writeRuleIPSets(table string, rules *strings.Builder, ipsets nft_ipsets, setNames map[string]string) {
	for name, set := range ipsets {
		// Generate short name for set without collisions:
		shortName, exists := setNames[name]
		if !exists {
			logging.LogWarning(nft_prefix, "SKIP SET: Can't find set for ", name)
			continue
		}

		// Add Sets
		replacer := strings.NewReplacer(
			"<TABLE>", table,
			"<SET>", nft_ip4+shortName, "<TYPE>", "ipv4_addr",
			"<SET6>", nft_ip6+shortName, "<TYPE6>", "ipv6_addr",
		)
		replacer.WriteString(rules, nft_add_set)
		replacer.WriteString(rules, nft_add_set_6)

		// Fill Set:
		ipv4, ipv6 := sortIPv46(set)
		replacer = strings.NewReplacer(
			"<TABLE>", table,
			"<SET>", nft_ip4+shortName, "<EL>", strings.Join(ipv4, ","),
			"<SET6>", nft_ip6+shortName, "<EL6>", strings.Join(ipv6, ","),
		)
		if len(ipv4) > 0 {
			replacer.WriteString(rules, nft_add_el)
		}
		if len(ipv6) > 0 {
			replacer.WriteString(rules, nft_add_el_6)
		}
	}
}

func (n *NFT) writeRuleChains(table string, priority string, rules *strings.Builder) {
	replacer := strings.NewReplacer(
		"<TABLE>", table,
		"<PRIORITY>", "0", "<POLICY>", "accept", // Set priority, Set policy drop
	)
	replacer.WriteString(rules, nft_chain)
}

func (n *NFT) writeRuleHeader(table string, rules *strings.Builder) {
	// TODO ... Header
}

func (n *NFT) writeRuleFooter(table string, rules *strings.Builder, setNames map[string]string) {
	for full, short := range setNames {
		replacer := strings.NewReplacer(
			"<TABLE>", table,
			"<NAME>", full,
			"<SET>", nft_ip4+short, "<SET6>", nft_ip6+short,
		)
		replacer.WriteString(rules, nft_footer)
	}

	// TODO ... Footer
}

func (n *NFT) writeRuleNIDS(table string, rules *strings.Builder, state *state) {
	if !state.Config.NIDSEnable {
		return
	}

	ports := sliceIntToStr(nidsState.nPorts)
	if len(ports) > 0 {
		replacer := strings.NewReplacer(
			"<TABLE>", table,
			"<PORTS>", fmt.Sprintf("tcp dport { %s }", strings.Join(ports, ",")),
		)
		replacer.WriteString(rules, nft_nids)
	}
}

func (n *NFT) writeRuleStaticSet(table string, rules *strings.Builder, state *state, setNames map[string]string) {
	// Fill static sets
	for _, set := range state.Config.StaticSetList {
		shortName, exists := setNames[set.Name]
		if !exists {
			logging.LogWarning(nft_prefix, "SKIP SERVICE: Can't find set for ", set.Name)
			logging.LogDebug(nft_prefix, "Existed names: ", setNames)
			continue
		}

		target := n.staticTarget(set.Target)
		if target == "" {
			continue
		}

		replacer := strings.NewReplacer(
			"<TABLE>", table,
			"<SADDR>", "@"+nft_ip4+shortName,
			"<SADDR6>", "@"+nft_ip6+shortName,
			"<TARGET>", target,
		)
		replacer.WriteString(rules, nft_static_rule)
		replacer.WriteString(rules, nft_static_rule_6)
	}
}

func (n *NFT) writeRuleServices(table string, rules *strings.Builder, state *state, setNames map[string]string) {
	// Fill services:
	for _, srv := range state.NodeServices {
		tcpRules, udpRules := portsAsRules(srv.Ports)
		shortName, exists := setNames[srv.Name]
		if !exists {
			logging.LogWarning(nft_prefix, "SKIP SERVICE: Can't find set for ", srv.Name)
			logging.LogDebug(nft_prefix, "Existed names: ", setNames)
			continue
		}
		if len(tcpRules) > 0 {
			tcpReplacer := strings.NewReplacer(
				"<TABLE>", table,
				"<SADDR>", "@"+nft_ip4+shortName,
				"<SADDR6>", "@"+nft_ip6+shortName,
				"<PORTS>", tcpRules,
			)
			tcpReplacer.WriteString(rules, nft_rule)
			tcpReplacer.WriteString(rules, nft_rule_6)
		}
		if len(udpRules) > 0 {
			udpReplacer := strings.NewReplacer(
				"<TABLE>", table,
				"<SADDR>", "@"+nft_ip4+shortName,
				"<SADDR6>", "@"+nft_ip6+shortName,
				"<PORTS>", udpRules,
			)
			udpReplacer.WriteString(rules, nft_rule)
			udpReplacer.WriteString(rules, nft_rule_6)
		}
	}
}

func portsAsRules(ports []bPort) (tcpExpr string, udpExpr string) {
	// Fetch unique port-strings:
	uniqTCP := make(map[string]bool)
	uniqUDP := make(map[string]bool)
	for _, port := range ports {
		// Get port or range ports
		str := strings.Replace(port.Range(), ":", "-", 1)
		if port.Protocol == PROTOCOL_TCP {
			uniqTCP[str] = true
		} else {
			uniqUDP[str] = true // append(udp, str)
		}
	}
	// Collect ports
	tcp := make([]string, 0)
	udp := make([]string, 0)
	for ports, _ := range uniqTCP {
		tcp = append(tcp, ports)
	}
	for ports, _ := range uniqUDP {
		udp = append(udp, ports)
	}
	// Fill rules:
	if len(tcp) > 0 {
		tcpExpr = fmt.Sprintf("tcp dport { %s }", strings.Join(tcp, ", "))
	}
	if len(udp) > 0 {
		udpExpr = fmt.Sprintf("udp dport { %s }", strings.Join(udp, ", "))
	}
	return
}

func (n *NFT) staticTarget(tgt string) string {
	switch tgt {
	case "NOOP":
		return "" // do nothing.
	case "LOG":
		return "log group 402"
	case "ACCEPT":
		return "accept"
	case "REJECT":
		return "reject"
	case "DROP":
		return "drop"
	}
	logging.LogWarning(nft_prefix, "Unexpected TARGET for static rule: ", tgt)
	return "" // do nothing
}

// Real Server calls:
// nftables: Apply rules (use tmp file)
func (b *prodBinNFT) ApplyRules(rules string) error {
	// Write rule to file:
	if f, e := os.OpenFile(nft_rule_file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); e == nil {
		defer f.Close()
		_, e = f.WriteString(rules)
		if e != nil {
			logging.LogWarning(nft_prefix, "Can't write rules to", nft_rule_file, ":", e.Error())
			return e
		}
	} else {
		logging.LogWarning(nft_prefix, "Can't write rules to", nft_rule_file, ":", e.Error())
		return e
	}

	// Apply
	out, err := run(&rules, "nft", "-f", nft_rule_file)
	if err != nil {
		logging.LogWarning(nft_prefix, "Failed to apply nft rules: ", out)
		logging.LogDebug("Failed rules:\n", rules)
		//return errors.New(out)
		return err
	}
	return nil
}

// nftables: List table befw
func (b *prodBinNFT) ListRuleset(table string) (string, error) {
	out, err := run(nil, "nft", "list", "table", "inet", table)
	if err != nil {
		logging.LogWarning(nft_prefix, "Failed to get list table ", table, ":", out)
	}
	return out, err
}

// Correct set names: nft supports only 16-length names for sets
func nftSetName(name string, inUse map[string]string) string {
	const SHORTABLE = 25
	const MAX = 11
	// Generate name or short name
	coolName := name

	// Cut port parts ('_tcp_123', '_udp_123')
	if i := strings.Index(coolName, "_tcp_"); i > 0 {
		coolName = coolName[:i]
	} else if i := strings.Index(coolName, "_udp_"); i > 0 {
		coolName = coolName[:i]
	}

	// Cut length if long
	switch {
	case len(coolName) > SHORTABLE:
		coolName = hashMD5(name)[:MAX]
	case len(coolName) > MAX:
		coolName = cutSetName(coolName, MAX)
	}

	// Check for collisions:
	if _, exists := inUse[coolName]; exists {
		coolName = hashMD5(name)[:MAX]
	}
	_, exists := inUse[coolName]
	for exists {
		// ... collisions - generate random
		coolName = getRandomString()[:MAX]
		_, exists = inUse[coolName]
	}
	inUse[coolName] = name

	return coolName
}
