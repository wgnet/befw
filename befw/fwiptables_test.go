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
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestKeepConsistent(t *testing.T) {
	s, fw := dummyState()

	var ok bool = false
	fw.ipsetApply = func(name, rules string) error {
		fw.appliedIPSet[name] = rules
		return nil
	}
	fw.rulesApply = func(rules string) error {
		fw.appliedRules = rules
		return nil
	}
	fw.rules6Apply = func(rules string) error {
		fw.appliedRules6 = rules
		return nil
	}
	fw.Apply(&s)

	// Ipset: Need to restore
	ok = true
	fw.isIpsetConsistent = func() bool { return false }
	fw.ipsetApply = func(name, rules string) error {
		ok = true
		return nil
	}
	fw.KeepConsistent()
	if !ok {
		t.Error("Not OK")
	}

	// Ipset: No need to restore
	fw.isIpsetConsistent = func() bool { return true }
	fw.ipsetApply = func(name, rules string) error { ok = false; return nil }
	fw.KeepConsistent()
	if !ok {
		t.Error("Not OK")
	}

	// Rules: Need to restore
	ok = false
	fw.isRulesConsistent = func() bool { return false }
	fw.rulesApply = func(rules string) error { ok = true; return nil }
	fw.KeepConsistent()
	if !ok {
		t.Error("Not OK")
	}

	// Rules: No need to restore
	ok = true
	fw.isRulesConsistent = func() bool { return true }
	fw.rulesApply = func(rules string) error { ok = false; return nil }
	fw.KeepConsistent()
	if !ok {
		t.Error("Not OK")
	}

	// Rules6: Need
	ok = false
	fw.isRules6Consistent = func() bool { return false }
	fw.rules6Apply = func(rules string) error { ok = true; return nil }
	fw.KeepConsistent()
	if !ok {
		t.Error("Not OK")
	}

	// Rules6: No need
	ok = false
	fw.isRules6Consistent = func() bool { return false }
	fw.rules6Apply = func(rules string) error { ok = true; return nil }
	fw.KeepConsistent()
	if !ok {
		t.Error("Not OK")
	}
}

func TestApply(t *testing.T) {
	s, fw := dummyState()
	var ipsetResult, rulesResult string = "", ""
	fw.ipsetApply = func(name, rules string) error { ipsetResult += rules; return nil }
	fw.rulesApply = func(rules string) error { rulesResult += rules; return nil }

	fw.Apply(&s)

	// Expect patterns in output
	expects(rulesResult, []string{
		"-I BEFW 1 -m set --match-set rules_allow src -j ACCEPT",
		"-I BEFW 2 -m set --match-set rules_deny src -j REJECT",
	}, t)
	if ENABLE_IPT_MULTIPORT {
		expects(rulesResult, []string{
			"-A BEFW -p tcp -m multiport --dports 10,8080:8090 -m set --set B src -j ACCEPT",
			"-A BEFW -p tcp -m multiport --dports 10,8080:8090 -j DROP",
			"-A BEFW -p tcp -m multiport --dports 20,8085:9090 -m set --set C src -j ACCEPT",
			"-A BEFW -p tcp -m multiport --dports 20,8085:9090 -j DROP",
			"-A BEFW -p tcp -m multiport --dports 30 -m set --set D src -j ACCEPT",
		}, t)
	} else {
		expects(rulesResult, []string{
			"-A BEFW -p tcp --dport 10 -m set --match-set B src -j ACCEPT",
			"-A BEFW -p tcp --dport 8080:8090 -m set --match-set B src -j ACCEPT",
			"-A BEFW -p tcp --dport 20 -m set --match-set C src -j ACCEPT",
			"-A BEFW -p tcp --dport 8085:9090 -m set --match-set C src -j ACCEPT",
		}, t)
	}

	// Expect pattrins in ipset output
	expects(ipsetResult, []string{
		"add tmp_[a-zA-Z0-9]* 1.2.3.1/32",
		"add tmp_[a-zA-Z0-9]* 1.2.3.2/32",
		"add tmp_[a-zA-Z0-9]* 1.2.3.3/32",
		"add tmp_[a-zA-Z0-9]* 1.2.3.4/32",
		"add tmp_[a-zA-Z0-9]* 1.2.3.6/32",
		"add tmp_[a-zA-Z0-9]* 0.0.0.0/1",
		"add tmp6_[a-zA-Z0-9]* ::/1",
		"add tmp_[a-zA-Z0-9]* 128.0.0.0/1",
		"swap tmp_[a-zA-Z0-9]* A",
		"swap tmp_[a-zA-Z0-9]* B",
		"swap tmp_[a-zA-Z0-9]* C",
	}, t)

	// Unexpect pattrins in ipset output
	unexpects(ipsetResult, []string{"add tmp_[a-zA-Z0-9]* 42\\.2\\.3\\.4",
		"add tmp_[a-zA-Z0-9]* 5\\.1\\.",
	}, t)

	if strings.Count(ipsetResult, "create rules_allow hash:net") != 1 {
		t.Error("Expect rules_allow only once:\n", ipsetResult)
	}
	if strings.Count(ipsetResult, "create rules_deny hash:net") != 1 {
		t.Error("Expect rules_deny only once:\n", ipsetResult)
	}
	if strings.Count(ipsetResult, "create A hash:net") != 1 {
		t.Error("Expect service A only once:\n", ipsetResult)
	}
	if strings.Count(ipsetResult, "create B hash:net") != 1 {
		t.Error("Expect service B only once:\n", ipsetResult)
	}
	if ENABLE_IPT_MULTIPORT {
		if strings.Count(rulesResult, "-A BEFW -p tcp -m multiport --dports 10,8080:8090 -m set --set B src -j ACCEPT") != 1 {
			t.Error("Expect rules B exact once:\n", rulesResult)
		}
		if strings.Count(rulesResult, "-A BEFW -p tcp -m multiport --dports 20,8085:9090 -m set --set C src -j ACCEPT") != 1 {
			t.Error("Expect rules C exact once:\n", rulesResult)
		}
	}
}

func TestRulesGenerate(t *testing.T) {
	s, fw := dummyState()
	test := fw.rulesGenerate(&s, s.StaticIPSets, false)

	// Expect patterns in output
	expects(test, []string{
		"-I BEFW 1 -m set --match-set rules_allow src -j ACCEPT",
		"-I BEFW 2 -m set --match-set rules_deny src -j REJECT",
	}, t)
	if ENABLE_IPT_MULTIPORT {
		expects(test, []string{
			"-A BEFW -p tcp -m multiport --dports 10,8080:8090 -m set --set B src -j ACCEPT",
			"-A BEFW -p tcp -m multiport --dports 10,8080:8090 -j DROP",
		}, t)
	}
}

func TestIpsetGenerateServices(t *testing.T) {
	s, fw := dummyState()

	var result string = ""
	for _, srv := range s.NodeServices {
		var set []string = make([]string, 10)
		for _, ipset := range srv.Clients {
			if ipset.isExpired() {
				continue
			}
			set = append(set, ipset.CIDR.String())
		}
		result += fw.ipsetGenerate(srv.Name, set)
	}
	expects(result, []string{"add tmp_[a-zA-Z0-9]* 0.0.0.0/1",
		"add tmp_[a-zA-Z0-9]* 128.0.0.0/1",
	}, t)
	unexpects(result, []string{"add tmp_[a-zA-Z0-9]* 42\\.2\\.3.4",
		"add tmp_[a-zA-Z0-9]* 5\\.1\\.3.5/32",
	}, t)
}

func TestIpsetGenerateStaticSetList(t *testing.T) {
	s, fw := dummyState()
	var result string = ""
	for name, set := range s.StaticIPSets {
		result += fw.ipsetGenerate(name, set)
	}

	expects(result, []string{"add tmp_[a-zA-Z0-9]* 0.0.0.0/1",
		"add tmp_[a-zA-Z0-9]* 192.168.1.1/32",
		"create rules_allow hash:net",
		"swap tmp_[a-zA-Z0-9]* A",
		"swap tmp_[a-zA-Z0-9]* rules_allow",
	}, t)
}

func TestIpsetGenerateConstSetList(t *testing.T) {
	s, fw := dummyState()

	// Check expectations
	expects := []string{"swap tmp_", "destroy tmp_", "create tmp_"}
	for _, set := range s.Config.StaticSetList {
		result := fw.ipsetGenerate(set.Name, nil)

		if !strings.Contains(result, fmt.Sprintf("create %s hash:net", set.Name)) {
			t.Errorf("Doesn't contain '%s' in '%s'", set.Name, result)
		}
		for _, expect := range expects {
			if !strings.Contains(result, fmt.Sprintf("create %s hash:net", set.Name)) {
				t.Errorf("Doesn't contain '%s' in '%s'", expect, result)
			}
		}
	}
}

// Test IPv6 support (ipset)
func TestIpsetV6(t *testing.T) {
	s, fw := dummyState()
	name := "TestService"
	srv6 := asService(name, []string{"22/tcp"}, []string{"4.4.4.4/28", "::1:5ee:bad:c0de/80"})
	s.NodeServices = append(s.NodeServices, srv6)

	result := ""
	fw.ipsetApply = func(name, rules string) error { result += rules; return nil }

	err := fw.Apply(&s)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}

	// Expected
	if !strings.Contains(result, name) {
		t.Errorf("Expect name in result:\n%s", result)
	}
	if !strings.Contains(result, "4.4.4.0/28") {
		t.Errorf("Expect correct IPv4 mask in result:\n%s", result)
	}

	if !strings.Contains(result, name+V6) {
		t.Errorf("Expect name_v6 in result:\n%s", result)
	}
	if !strings.Contains(result, "family inet6") {
		t.Errorf("Expect family inet6 mask in result:\n%s", result)
	}
	if !strings.Contains(result, "::1:0:0:0/80") {
		t.Errorf("Expect correct IPv6 mask in result:\n%s", result)
	}
}

func TestIptablesV6(t *testing.T) {
	s, fw := dummyState()

	result := ""
	resultv6 := ""
	fw.rulesApply = func(rules string) error { result += rules; return nil }
	fw.rules6Apply = func(rules string) error { resultv6 += rules; return nil }

	// Exist v6
	name := "TestService"
	srv6 := asService(name, []string{"22/tcp"}, []string{"4.4.4.4/28", "::1:5ee:bad:c0de/80"})
	s.NodeServices = append(s.NodeServices, srv6)
	err := fw.Apply(&s)
	if err != nil {
		t.Fail()
	}
	if !strings.Contains(result, name) {
		t.Errorf("Expect '%s' in:\n%s", name, result)
	}
	if !strings.Contains(resultv6, name+V6) {
		t.Errorf("Expect '%s' in:\n%s", name+V6, resultv6)
	}
}

// ==========[ Util Func ]==========

func dummyState() (state, FwIptables) {

	s := state{
		StaticIPSets: map[string][]string{
			"A": []string{"1.2.3.1/32", "0.0.0.0/0", "10.10.10.10/28", "192.168.1.1/32", "42.2.3.4", "::0/0"},
			"B": []string{"1.2.3.2/32", "0.0.0.0/0", "10.10.10.10/28", "192.168.1.1/32", "42.2.3.4"},
		},
		NodeServices: []bService{
			asService("B", []string{"10/tcp", "8080:8090"}, []string{"1.2.3.3/32", "0.0.0.0/0", "10.0.0.0/12", "5.1.1.3/32", "42.2.3.4"}),
			asService("C", []string{"20/tcp", "8085:9090"}, []string{"1.2.3.4/32", "10.0.0.0/12", "1.2.3.6/32", "43.2.3.4", "5.1.1.4/32"}),
			asService("D", []string{"30/tcp"}, []string{"1.2.3.4/32", "10.0.0.0/12", "1.2.3.6/32", "43.2.3.4", "5.1.1.4/32"}),
			asService("E", []string{}, []string{"1.2.3.4/32", "10.0.0.0/12", "1.2.3.6/32", "43.2.3.4", "5.1.1.4/32"}),
		},
	}
	s.Config = &config{
		StaticSetList: staticIPSetList,
	}
	s.fillMandatoryIPSet()
	var fw FwIptables = NewIptables()
	// IPv4
	fw.ipsetApply = func(name, rules string) error { return nil }
	fw.rulesApply = func(rules string) error { return nil }
	fw.isIpsetConsistent = func() bool { return true }
	fw.isRulesConsistent = func() bool { return true }
	// IPv6
	fw.rules6Apply = func(rules string) error { return nil }
	fw.isRules6Consistent = func() bool { return true }

	return s, fw
}

func asService(name string, ports []string, clients []string) bService {
	srv := bService{Name: name, Ports: make([]bPort, 0), Clients: make([]bClient, 0)}
	for _, port := range ports {
		p, e := NewBPort(port)
		if e != nil {
			continue
		}
		srv.Ports = append(srv.Ports, *p)
	}
	for _, cl := range clients {
		var tm int64 = time.Now().Unix() - 10 + 1000
		if strings.HasPrefix(cl, "5.1") {
			tm -= 2000
		} // Expired
		_, r, _ := net.ParseCIDR(cl)
		if r == nil {
			continue
		}
		srv.Clients = append(srv.Clients, bClient{CIDR: r, Expiry: tm})
	}
	return srv
}

func expects(data string, expects []string, t *testing.T) bool {
	for _, expect := range expects {
		m, e := regexp.MatchString(expect, data)
		if e != nil {
			t.Error(e.Error())
			t.FailNow()
		}
		if !m {
			t.Errorf("Expected '%s' not found in: \n%s", expect, data)
			return false
		}
	}
	return true
}

func unexpects(data string, expects []string, t *testing.T) bool {
	for _, expect := range expects {
		m, e := regexp.MatchString(expect, data)
		if e != nil {
			t.Error(e.Error())
			t.FailNow()
		}
		if m {
			t.Errorf("NOT Expected '%s' found in: \n%s", expect, data)
			return false
		}
	}
	return true
}
