/**
 * Copyright 2018-2023 Wargaming Group Limited
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
	"testing"
)

func TestIPRegex(t *testing.T) {
	rx := regexp.MustCompile("^" + REGEXP_IP4 + "$")
	// IPv4
	good := []string{"0.0.0.0", "1.2.3.4", "255.255.255.255", "10.0.255.6"}
	bad := []string{"0.0.0.0.0", "1.2.3", "256.255.255.255", "01.2.3.4", "1.2.3.4.", "1.2.3.4a"}
	for _, item := range good {
		if !rx.MatchString(item) {
			t.Errorf("Expect as good IP: %s", item)
		}
	}
	for _, item := range bad {
		if rx.MatchString(item) {
			t.Errorf("Expect as bad IP: %s", item)
		}
	}

	// IPv6
	rx = regexp.MustCompile("^" + REGEXP_IP6 + "$")
	good = []string{"::", "::1", "cafe::", "1:2:3::7:8", "1:2:3:4:5:6:7:8", "0123:4567:89ab:cdef:0123:4567:89ab:cdef", "CaFe::5eE"}
	bad = []string{"::1::8", "1:2:3:4:5:6:7:8:9", "0123:4567:89ab:cdef:0123:4567:89ab", "1:2:3:0abc4:5:6:7:8:9", ":CaFe::5eE", ":1:2:3::7:8"}
	for _, item := range good {
		if !rx.MatchString(item) {
			t.Errorf("Expect as good IP: %s", item)
		}
	}
	for _, item := range bad {
		if rx.MatchString(item) {
			t.Errorf("Expect as bad IP: %s", item)
		}
	}

	// Net32
	rx = regexp.MustCompile("^" + REGEXP_NET_32 + "$")
	good = []string{"", "/0", "/1", "/12", "/32"}
	bad = []string{"/", "/-", "/33", "/128", "/129"}
	for _, item := range good {
		if !rx.MatchString(item) {
			t.Errorf("Expect as good Net32: %s", item)
		}
	}
	for _, item := range bad {
		if rx.MatchString(item) {
			t.Errorf("Expect as bad Net32: %s", item)
		}
	}

	// Net128
	rx = regexp.MustCompile("^" + REGEXP_NET_128 + "$")
	good = []string{"", "/0", "/1", "/12", "/32", "/100", "/128"}
	bad = []string{"/", "/-", "/129", "/1000"}
	for _, item := range good {
		if !rx.MatchString(item) {
			t.Errorf("Expect as good Net128: %s", item)
		}
	}
	for _, item := range bad {
		if rx.MatchString(item) {
			t.Errorf("Expect as bad Net128: %s", item)
		}
	}
}

// Test bin util.
func TestCall(t *testing.T) {
	if !ENABLE_BIN_CALLS {
		return
	} // Skip if not allowed
	// Echo call
	stdout, err := run(nil, "echo", "42")
	if err != nil {
		t.Fail()
	}
	if stdout != "42\n" {
		t.Error("Bad response: `", stdout, "`")
	}

	// Stdin echo|head test
	stdin := "123456"
	stdout, err = run(&stdin, "head", "-c2")
	if err != nil {
		t.Fail()
	}
	if stdout != "12" {
		t.Error("Bad response (head): `", stdout, "`")
	}

	// Error command
	_, err = run(nil, "exit", "3")
	if err == nil {
		t.Error("Expect error")
	}
}

func TestCutIPSet(t *testing.T) {
	table := map[string]string{
		"test_tcp_2200": "test_tcp_2200",
		"very_long_service_name_abcd_1234_tcp_2200": "ve_lo_se_na_ab_12_tc_2200",
	}
	for i, x := range table {
		if v := correctIPSetName(i, 31); v != x {
			t.Error("correctIPSetName: ", i, "->", v, "!=", x)
		}
	}
}

func TestGetRandomString(t *testing.T) {
	for i := 0; i < 255; i++ {
		if v := getRandomString(); len(v) != 25 {
			t.Error("Non-25 string:", v)
		}
	}
}

func TestGetBinary(t *testing.T) {
	// get default binaries for any *nix
	testCases := []string{
		"sh", "cat", "ls",
	}
	for _, k := range testCases {
		if getBinary(k) == "false" {
			t.Error("can't find binary ", k)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	if isIPv6("1.2.3.4") {
		t.Fail()
	}
	if !isIPv6("::1:5ee:bad:c0de") {
		t.Fail()
	}
}
