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
    "testing"
    "fmt"
    "strings"
    "regexp"
    "net"
    "time"
)

func dummyState() (state, FwIptables) {
    asService := func(name string, ports []string, clients []string) bService {
        srv := bService { Name: name, Ports: make([]bPort, 0), Clients: make([]bClient, 0) }
        for _, port := range ports {
            p, e := NewBPort(port)
            if e != nil { continue }
            srv.Ports = append(srv.Ports, *p)
        }
        for _, cl := range clients {
            var tm int64 = time.Now().Unix() - 10 + 1000
            if cl == "1.2.3.5/32" { tm -= 2000 }
            _, r, _ := net.ParseCIDR(cl)
            srv.Clients = append(srv.Clients, bClient{ CIDR: r, Expiry: tm })
        }
        return srv
    }

    s := state {
        StaticIPSets:   map[string][]string {
            "A": []string{"0.0.0.0/0", "1.2.3.4", "10.10.10.10/28", "192.168.1.1/32"},
            "B": []string{"0.0.0.0/0", "1.2.3.4", "10.10.10.10/28", "192.168.1.1/32"},
        },
        NodeServices: []bService{
            asService("A", []string{"1/udp", "22"}, []string{"0.0.0.0/0", "1.2.3.1/32", "4.2.3.4"}),
            asService("B", []string{"80/tcp", "8080:8090"}, []string{"10.0.0.0/12", "1.2.3.5/32", "42.2.3.4"}),
        },
    }
    s.Config = &config {
         StaticSetList:  staticIPSetList,
    }
    s.fillMandatoryIPSet()
    var fw FwIptables = NewIptables()
    fw.ipsetApply = func(name, rules string) error { return nil; }
    fw.rulesApply = func(rules string) error { return nil;}
    fw.isIpsetConsistent = func() bool { return false }
    fw.isRulesConsistent = func() bool { return false }

    return s, fw
}

func expects(data string, expects []string, t *testing.T) bool {
    for _, expect := range expects {
        m, e := regexp.MatchString(expect, data)
        if e != nil { t.Error(e.Error()); t.FailNow() }
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
        if e != nil { t.Error(e.Error()); t.FailNow() }
        if m {
            t.Errorf("NOT Expected '%s' not found in: \n%s", expect, data)
            return false
        }
    }
    return true
}

func TestKeepConsistent(t *testing.T) {
    s, fw := dummyState()

    var ok bool = false
    fw.ipsetApply = func(name, rules string) error {
        fw.appliedIPSet[name] = rules
        return nil }
    fw.rulesApply = func(rules string) error {
        fw.appliedRules = rules
        return nil }
    fw.Apply(&s)

    // Ipset: Need to restore
    ok = true
    fw.isIpsetConsistent = func() bool { return false }
    fw.ipsetApply = func(name, rules string) error {
        ok = true
        return nil }
    fw.KeepConsistent()
    if !ok { t.Error("Not OK") }

    // Ipset: No need to restore
    fw.isIpsetConsistent = func() bool { return true }
    fw.ipsetApply = func(name, rules string) error { ok = false; return nil }
    fw.KeepConsistent()
    if !ok { t.Error("Not OK") }

    // Rules: Need to restore
    ok = false
    fw.isRulesConsistent = func() bool { return false }
    fw.rulesApply = func(rules string) error { ok = true; return nil }
    fw.KeepConsistent()
    if !ok { t.Error("Not OK") }

    // Rules: No need to restore
    ok = true
    fw.isRulesConsistent = func() bool { return true }
    fw.rulesApply = func(rules string) error { ok = false; return nil }
    fw.KeepConsistent()
    if !ok { t.Error("Not OK") }
}

func TestApply(t *testing.T) {
    s, fw := dummyState()
    var ipsetResult, rulesResult string = "", ""
    fw.ipsetApply = func(name, rules string) error { ipsetResult += rules;return nil; }
    fw.rulesApply = func(rules string) error { rulesResult += rules; return nil;}

    fw.Apply(&s)

    // Expect patterns in output
    expects(rulesResult, []string{
        "-I BEFW 1 -m set --match-set rules_allow src -j ACCEPT",
        "-I BEFW 2 -m set --match-set rules_deny src -j REJECT",
        "-A BEFW -p udp -m multiport --dports 1 -m set --set A src -j ACCEPT",
        "-A BEFW -p udp -m multiport --dports 1 -j DROP",
        "-A BEFW -p tcp -m multiport --dports 80, 8080:8090 -m set --set B src -j ACCEPT",
        "-A BEFW -p tcp -m multiport --dports 80, 8080:8090 -j DROP",
    }, t)

    // Expect pattrins in ipset output
    expects(ipsetResult, []string{"add tmp_[a-zA-Z0-9]* 0.0.0.0/1",
                        "add tmp_[a-zA-Z0-9]* 128.0.0.0/1",
                        "swap tmp_[a-zA-Z0-9]* A",
                        }, t)

    // Unexpect pattrins in ipset output
    unexpects(ipsetResult,[]string{"add tmp_[a-zA-Z0-9]* 42.2.3.4",
                        "add tmp_[a-zA-Z0-9]* 1.2.3.5/32",
                        }, t)

    if strings.Count(ipsetResult, "create rules_allow hash:net") != 1 { t.Error("Expect rules_allow only once:\n", ipsetResult); }
    if strings.Count(ipsetResult, "create rules_deny hash:net") != 1 { t.Error("Expect rules_deny only once:\n", ipsetResult) }
    if strings.Count(ipsetResult, "create A hash:net") != 1 { t.Error("Expect service A only once:\n", ipsetResult) }
    if strings.Count(ipsetResult, "create B hash:net") != 1 { t.Error("Expect service B only once:\n", ipsetResult) }
    if strings.Count(rulesResult, "-A BEFW -p tcp -m multiport --dports 22 -m set --set A src -j ACCEPT") != 1 { t.Error("Expect rules A only once:\n", rulesResult) }
    if strings.Count(rulesResult, "-A BEFW -p udp -m multiport --dports 1 -m set --set A src -j ACCEPT") != 1 { t.Error("Expect rules A only once:\n", rulesResult) }
    if strings.Count(rulesResult, "-A BEFW -p tcp -m multiport --dports 80, 8080:8090 -m set --set B src -j ACCEPT") != 1 { t.Error("Expect rules B only once:\n", rulesResult) }

    // Show Real applied rules
    // fmt.Println(ipsetResult)
    // fmt.Println(rulesResult)
}

func TestRulesGenerate(t *testing.T) {
    s, fw := dummyState()
    test := fw.rulesGenerate(&s)

    // Expect patterns in output
    expects(test, []string{
        "-I BEFW 1 -m set --match-set rules_allow src -j ACCEPT",
        "-I BEFW 2 -m set --match-set rules_deny src -j REJECT",
        "-A BEFW -p udp -m multiport --dports 1 -m set --set A src -j ACCEPT",
        "-A BEFW -p udp -m multiport --dports 1 -j DROP",
        "-A BEFW -p tcp -m multiport --dports 80, 8080:8090 -m set --set B src -j ACCEPT",
        "-A BEFW -p tcp -m multiport --dports 80, 8080:8090 -j DROP",
    }, t)
}

func TestIpsetGenerateServices(t *testing.T) {
    s, fw := dummyState()

    var result string = ""
    for _, srv := range s.NodeServices {
        var set []string = make([]string, 10)
        for _, ipset := range srv.Clients {
            if ipset.isExpired() { continue }
            set = append(set, ipset.CIDR.String())
        }
        result += fw.ipsetGenerate(srv.Name, set)
    }
    expects(result, []string{"add tmp_[a-zA-Z0-9]* 0.0.0.0/1",
                        "add tmp_[a-zA-Z0-9]* 128.0.0.0/1",
                        "swap tmp_[a-zA-Z0-9]* A",
                        }, t)
    unexpects(result, []string{"add tmp_[a-zA-Z0-9]* 42.2.3.4",
                        "add tmp_[a-zA-Z0-9]* 1.2.3.5/32",
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
    expects := []string{ "swap tmp_", "destroy tmp_", "create tmp_"}
    for _, set  := range s.Config.StaticSetList {
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
