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
	"regexp"
	"strings"
	"testing"
)

type mockNFTc7bin struct {
	rules string
}

func TestMockC7Bin(t *testing.T) {
	nft := NFTc7{bin: &mockNFTc7bin{}}
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

func TestRuleGenC7(t *testing.T) {
	nft := NFTc7{bin: &mockNFTc7bin{}}
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
	// dbg("NFTc7 RuleFile:\n", nft.RulesApplied, "\n -- EOF --")
	// dbg("NFTc7 TMP RuleFile:\n", nft.RulesTMP, "\n -- EOF --")
}

func (m *mockNFTc7bin) ApplyRules(rules string) error {
	m.rules = rules
	return nil
}

func (m *mockNFTc7bin) ListRuleset(table string) (string, error) {
	return m.rules, nil
}
