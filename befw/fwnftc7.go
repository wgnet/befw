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

/**
  Notes:  nftables v0.8 (with kernel 3.10) hangup on 'flush set' operations.
          Also it has lack of some functions: auto-merge, drop/create in one file, ...
          This NFTables provider is workaround for this limitations.
*/
// NFTc7 compitable with nftables v0.8 (c7 (CentOS 7), kernel 3.10).
type NFTc7 struct {
	RulesApplied     string
	RulesAppliedHash string
	RulesTMP         string
	RealHash         string

	bin binNFTc7
}

type binNFTc7 interface {
	ApplyRules(rules string) error
	ListRuleset(table string) (string, error)
}

type prodBinNFTc7 struct{}
type nftc7_ipsets = map[string][]string // Shortcut for type

// Table names:
const (
	nftc7_befw        = "befw"
	nftc7_befw_tmp    = "befw_tmp"
	nftc7_rule_file   = befwState + "/rules.nft"
	nftc7_prefix      = "[NFT] "
	nftc7_setname_max = 15
	nftc7_ip4         = "ip4_" // len <= 4
	nftc7_ip6         = "ip6_" // len <= 4
)

// Templates:
const (
	nftc7_table_reset   = "add table inet <TABLE>;\ndelete table inet <TABLE>;\nadd table inet <TABLE>;\n"
	nftc7_add_set       = "add set inet <TABLE> <SET> {type <TYPE>; flags interval;};\n"
	nftc7_add_set_6     = "add set inet <TABLE> <SET6> {type <TYPE6>; flags interval;};\n"
	nftc7_chain         = "add chain inet <TABLE> filter {type filter hook input priority <PRIORITY>; policy <POLICY>;};\n"
	nftc7_add_el        = "add element inet <TABLE> <SET> { <EL> };\n"
	nftc7_add_el_6      = "add element inet <TABLE> <SET6> { <EL6> };\n"
	nftc7_nids          = "add rule inet <TABLE> filter <PORTS> log group 402\n"
	nftc7_static_rule   = "add rule inet <TABLE> filter ip saddr <SADDR> <TARGET>;\n"
	nftc7_static_rule_6 = "add rule inet <TABLE> filter ip6 saddr <SADDR6> <TARGET>;\n"
	nftc7_rule          = "add rule inet <TABLE> filter ip saddr <SADDR> <PORTS> accept;\n"
	nftc7_rule_6        = "add rule inet <TABLE> filter ip6 saddr <SADDR6> <PORTS> accept;\n"
	nftc7_footer        = "# <NAME> - <SET> | <SET6>;\n"
)

// New instance of NFTc7:
func NewNFTc7() *NFTc7 {
	logging.LogDebug(nftc7_prefix, "Initialize NFTc7 (centos7) firewall provider")
	// Create directory for rule-file
	os.MkdirAll(befwState, 0755)

	nft := NFTc7{
		bin: &prodBinNFTc7{},
	}

	return &nft
}

// Implement Firewall interface:
func (n *NFTc7) Apply(state *state) error {
	logging.LogDebug(nftc7_prefix, "Run Apply state")

	// Generate rules:
	rulesBEFW := n.generateRuleFile(nftc7_befw, "0", state) + n.generateRuleInitTable(nftc7_befw_tmp)

	// Check if changed since last time
	hash := hashMD5(rulesBEFW)
	if n.RulesAppliedHash == hash {
		logging.LogDebug(nftc7_prefix, "SKIP APPLY. Rule was already applied")
		return nil
	}

	// Generate TMP rules:
	rulesBEFW_tmp := n.generateRuleFile(nftc7_befw_tmp, "-1", state) + n.generateRuleInitTable(nftc7_befw)

	// Apply (swap with tmp table)
	for _, rules := range []string{rulesBEFW_tmp, rulesBEFW} {
		err := n.bin.ApplyRules(rules)
		if err != nil {
			return err
		}
	}

	// Store hash
	ruleset, err := n.bin.ListRuleset(nftc7_befw)
	if err != nil {
		return err
	}
	n.RulesApplied = rulesBEFW
	n.RulesTMP = rulesBEFW_tmp
	n.RulesAppliedHash = hash
	n.RealHash = hashMD5(ruleset)

	logging.LogInfo(nftc7_prefix, "State was applied.") // TODO: Log whats new
	return nil
}

// Firewall:
func (n *NFTc7) KeepConsistent() error {
	logging.LogDebug(nftc7_prefix, "Run KeepConsistent.")
	// TODO Add counter of failrues - go to panic mode if many times in a row failed
	if len(n.RulesApplied) == 0 {
		logging.LogDebug(nftc7_prefix, "SKIP Consistency check: there is no applied rules yet.")
		return nil
	}
	ruleset, err := n.bin.ListRuleset(nftc7_befw)
	if err != nil {
		logging.LogDebug(nftc7_prefix, "Failed to list table: ", err)
		//return err
	}
	if err != nil || hashMD5(ruleset) != n.RealHash {
		logging.LogDebug(nftc7_prefix, "Consistency changed... Start restore")
		// Restore (tmp->rules)
		for _, rules := range []string{n.RulesTMP, n.RulesApplied} {
			err := n.bin.ApplyRules(rules)
			if err != nil {
				return err
			}
		}
		logging.LogWarning(nftc7_prefix, "Consistency recovered: state was reapplied.")
	}
	return nil
}

// Collect const, static and service clients  addresses to sets:
func (n *NFTc7) collectIPSets(state *state) nftc7_ipsets {
	ipsets := make(nftc7_ipsets) // Init result map

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

func (n *NFTc7) generateRuleInitTable(table string) string {
	rule := new(strings.Builder)
	n.writeRuleInit(table, rule)
	return rule.String()
}

func (n *NFTc7) generateRuleFile(table string, priority string, state *state) string {
	// Generate rules
	result := new(strings.Builder)

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

func (n *NFTc7) writeRuleInit(table string, rules *strings.Builder) {
	// Init (flush table)
	replacer := strings.NewReplacer(
		"<TABLE>", table,
	)
	replacer.WriteString(rules, nftc7_table_reset)
}

func (n *NFTc7) writeRuleIPSets(table string, rules *strings.Builder, ipsets nftc7_ipsets, setNames map[string]string) {
	for name, set := range ipsets {
		shortName, exists := setNames[name]
		if !exists {
			logging.LogWarning(nft_prefix, "SKIP SET: Can't find set for ", name)
			continue
		}
		// Add Sets
		replacer := strings.NewReplacer(
			"<TABLE>", table,
			"<SET>", nftc7_ip4+shortName, "<TYPE>", "ipv4_addr",
			"<SET6>", nftc7_ip6+shortName, "<TYPE6>", "ipv6_addr",
		)
		replacer.WriteString(rules, nftc7_add_set)
		replacer.WriteString(rules, nftc7_add_set_6)

		// Fill Set:
		ipv4, ipv6 := sortIPv46(set)
		replacer = strings.NewReplacer(
			"<TABLE>", table,
			"<SET>", nftc7_ip4+shortName, "<EL>", strings.Join(ipv4, ","),
			"<SET6>", nftc7_ip6+shortName, "<EL6>", strings.Join(ipv6, ","),
		)
		if len(ipv4) > 0 {
			replacer.WriteString(rules, nftc7_add_el)
		}
		if len(ipv6) > 0 {
			replacer.WriteString(rules, nftc7_add_el_6)
		}
	}
}

func (n *NFTc7) writeRuleChains(table string, priority string, rules *strings.Builder) {
	replacer := strings.NewReplacer(
		"<TABLE>", table,
		"<PRIORITY>", "0", "<POLICY>", "accept", // Set priority, Set policy drop
	)
	replacer.WriteString(rules, nftc7_chain)
}

func (n *NFTc7) writeRuleHeader(table string, rules *strings.Builder) {
	// TODO ... Header
}

func (n *NFTc7) writeRuleFooter(table string, rules *strings.Builder, setNames map[string]string) {
	// Write service name map
	for full, short := range setNames {
		replacer := strings.NewReplacer(
			"<NAME>", full,
			"<SET>", nftc7_ip4+short,
			"<SET6>", nftc7_ip6+short,
		)
		replacer.WriteString(rules, nftc7_footer)
	}
	// TODO ... Footer
}

func (n *NFTc7) writeRuleNIDS(table string, rules *strings.Builder, state *state) {
	if !state.Config.NIDSEnable {
		return
	}

	ports := sliceIntToStr(nidsState.nPorts)
	if len(ports) > 0 {
		replacer := strings.NewReplacer(
			"<TABLE>", table,
			"<PORTS>", fmt.Sprintf("tcp dport { %s }", strings.Join(ports, ",")),
		)
		replacer.WriteString(rules, nftc7_nids)
	}
}

func (n *NFTc7) writeRuleStaticSet(table string, rules *strings.Builder, state *state, setNames map[string]string) {
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
			"<SADDR>", "@"+nftc7_ip4+shortName,
			"<SADDR6>", "@"+nftc7_ip6+shortName,
			"<TARGET>", target,
		)
		replacer.WriteString(rules, nftc7_static_rule)
		replacer.WriteString(rules, nftc7_static_rule_6)
	}
}

func (n *NFTc7) writeRuleServices(table string, rules *strings.Builder, state *state, setNames map[string]string) {
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
				"<SADDR>", "@"+nftc7_ip4+shortName,
				"<SADDR6>", "@"+nftc7_ip6+shortName,
				"<PORTS>", tcpRules,
			)
			tcpReplacer.WriteString(rules, nftc7_rule)
			tcpReplacer.WriteString(rules, nftc7_rule_6)
		}
		if len(udpRules) > 0 {
			udpReplacer := strings.NewReplacer(
				"<TABLE>", table,
				"<SADDR>", "@"+nftc7_ip4+shortName,
				"<SADDR6>", "@"+nftc7_ip6+shortName,
				"<PORTS>", udpRules,
			)
			udpReplacer.WriteString(rules, nftc7_rule)
			udpReplacer.WriteString(rules, nftc7_rule_6)
		}
	}
}

func (n *NFTc7) staticTarget(tgt string) string {
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
	logging.LogWarning(nftc7_prefix, "Unexpected TARGET for static rule: ", tgt)
	return "" // do nothing
}

// Real Server calls:
// nftables: Apply rules (use tmp file)
func (b *prodBinNFTc7) ApplyRules(rules string) error {
	// Write rule to file:
	if f, e := os.OpenFile(nftc7_rule_file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); e == nil {
		defer f.Close()
		_, e = f.WriteString(rules)
		if e != nil {
			logging.LogWarning(nftc7_prefix, "Can't write rules to", nftc7_rule_file, ":", e.Error())
			return e
		}
	} else {
		logging.LogWarning(nftc7_prefix, "Can't write rules to", nftc7_rule_file, ":", e.Error())
		return e
	}

	// Apply
	out, err := run(&rules, "nft", "-f", nftc7_rule_file)
	if err != nil {
		logging.LogWarning(nftc7_prefix, "Failed to apply nft rules: ", out)
		logging.LogDebug("Failed rules:\n", rules)
		//return errors.New(out)
		return err
	}
	return nil
}

// nftables: List table befw
func (b *prodBinNFTc7) ListRuleset(table string) (string, error) {
	out, err := run(nil, "nft", "list", "table", "inet", table)
	if err != nil {
		logging.LogWarning(nftc7_prefix, "Failed to get list table ", table, ":", out)
	}
	return out, err
}
