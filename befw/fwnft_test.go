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
	"regexp"
	"strings"
	"testing"
)

type mockNFTbin struct {
	rules string
}

func TestShortNamesNFT(t *testing.T) {
	inUse := make(map[string]string)
	for _, name := range []string{"A", "A", "A", "default_prometheus_tcp_9110", "befw_vrf-backend_isolation_drop", "ssh_tcp_2200", "rules_allow", "test.srv2.stg-hiera_tcp_19080"} {
		nftSetName(name, inUse)
	}

	// Check expected shorts:
	for _, expected := range []string{"A", hashMD5("A")[:11], "defau_prome", hashMD5("befw_vrf-backend_isolation_drop")[:11], "rules_allow", "ssh"} {
		if _, ok := inUse[expected]; ok {
			continue
		}
		t.Error(fmt.Sprintf("Expected short-name not found: %s in %v", expected, inUse))
	}
}

func TestMockBin(t *testing.T) {
	nft := NFTc7{bin: &mockNFTbin{}}
	rules := "Fake rules"
	nft.bin.ApplyRules(rules)
	result, err := nft.bin.ListRuleset("")
	if err != nil {
		t.Fatal(err)
	}
	if result != rules {
		t.Error("Expect same rules")
	}

	// Test regex
	rx := regexp.MustCompile(`.*(\{\s*\}).*`)
	if !rx.MatchString("... { } ...") {
		t.Fatal()
	}
	if !rx.MatchString("....\n... { } ...") {
		t.Fatal()
	}
	if !rx.MatchString("....\n... { } ...\n...") {
		t.Fatal()
	}
}

func TestRuleGen(t *testing.T) {
	nft := NFT{bin: &mockNFTbin{}}
	state := testDummyState()

	if err := nft.Apply(&state); err != nil {
		t.Fatal(err)
	}

	// Check empty sets: {  }
	rx := regexp.MustCompile(`.*(\{\s*\}).*`)
	if rx.MatchString(nft.RulesApplied) {
		t.Error("Found empty set in rules ( {} ):\n > ", strings.Join(rx.FindAllString(nft.RulesApplied, -1), "\n > "))
	}
	// Check empty items: ,,
	rx = regexp.MustCompile(`.*(,,|\{\s*,).*`)
	if rx.MatchString(nft.RulesApplied) {
		t.Error("Found empty items in rules (,,):\n > ", strings.Join(rx.FindAllString(nft.RulesApplied, -1), "\n > "))
	}

	// Random rule check
	rx = regexp.MustCompile(`add element .* ip4_B \{.*10\.10\.10\.10\/28.*\}`)
	if !rx.MatchString(nft.RulesApplied) {
		t.Error("Expected element 10.10.10.10/28 for B")
	}

	// Double ports check
	rx = regexp.MustCompile(`.*(\{.*443, 443.*\}).*`)
	if rx.MatchString(nft.RulesApplied) {
		t.Error("Found double ports in rules ( {} ):\n > ", strings.Join(rx.FindAllString(nft.RulesApplied, -1), "\n > "))
	}

	// SKIP: It's OK.  Check dublicates
	// rx = regexp.MustCompile(`0\.0\.0\.0\/0.*0\.0\.0\.0/0`)
	// if rx.MatchString(nft.RulesApplied) {
	//     t.Error("Dublicate of elements 0.0.0.0/0")
	// }

	// TODO: Dev only:
	//dbg("NFT RuleFile:\n", nft.RulesApplied, "\n -- EOF --")
}

func (m *mockNFTbin) ApplyRules(rules string) error {
	m.rules = rules
	return nil
}

func (m *mockNFTbin) ListRuleset(table string) (string, error) {
	return m.rules, nil
}
